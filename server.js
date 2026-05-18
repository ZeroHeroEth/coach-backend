require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Auth middleware ────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

// ── Health check ───────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'Coach backend running' }));

// ── Profile ────────────────────────────────────────────────────────────────
app.get('/profile', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', req.user.id)
    .single();
  if (error && error.code !== 'PGRST116') return res.status(500).json({ error });
  res.json(data || null);
});

app.post('/profile', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('profiles')
    .upsert({ id: req.user.id, ...req.body })
    .select()
    .single();
  if (error) {
    console.error('Profile upsert error:', error);
    return res.status(500).json({ error });
  }
  res.json(data);
});

// ── Memory log ─────────────────────────────────────────────────────────────
app.get('/memory', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('memory_log')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(40);
  if (error) return res.status(500).json({ error });
  res.json(data || []);
});

app.post('/memory', requireAuth, async (req, res) => {
  const { facts } = req.body;
  if (!facts?.length) return res.json([]);
  const date = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const rows = facts.map(text => ({ user_id: req.user.id, text, date }));
  const { data, error } = await supabase.from('memory_log').insert(rows).select();
  if (error) return res.status(500).json({ error });

  // Keep only the 40 most recent
  const { data: all } = await supabase
    .from('memory_log')
    .select('id, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });
  if (all && all.length > 40) {
    const toDelete = all.slice(40).map(r => r.id);
    await supabase.from('memory_log').delete().in('id', toDelete);
  }
  res.json(data);
});

// ── Routines ───────────────────────────────────────────────────────────────
app.get('/routines', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('routines')
    .select('*')
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error });
  const result = {};
  (data || []).forEach(r => { result[r.type] = { sections: r.sections, source: r.source, updatedAt: r.updated_at }; });
  res.json(result);
});

app.post('/routines', requireAuth, async (req, res) => {
  const { type, sections, source } = req.body;
  const updated_at = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const { data, error } = await supabase
    .from('routines')
    .upsert({ user_id: req.user.id, type, sections, source: source || 'coach', updated_at },
             { onConflict: 'user_id,type' })
    .select()
    .single();
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.delete('/routines/:type', requireAuth, async (req, res) => {
  const { error } = await supabase
    .from('routines')
    .delete()
    .eq('user_id', req.user.id)
    .eq('type', req.params.type);
  if (error) return res.status(500).json({ error });
  res.json({ success: true });
});

// ── Conversations ──────────────────────────────────────────────────────────
app.get('/conversations', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('conversations')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error });
  res.json(data || []);
});

// ── Chat ───────────────────────────────────────────────────────────────────
app.post('/chat', requireAuth, async (req, res) => {
  const { messages, userMessage } = req.body;
  if (!messages?.length) return res.status(400).json({ error: 'No messages' });

  // Load full context from DB
  const [profileRes, memoryRes, routinesRes] = await Promise.all([
    supabase.from('profiles').select('*').eq('id', req.user.id).single(),
    supabase.from('memory_log').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(40),
    supabase.from('routines').select('*').eq('user_id', req.user.id)
  ]);

  const profile = profileRes.data;
  const memory = memoryRes.data || [];
  const routinesByType = {};
  (routinesRes.data || []).forEach(r => { routinesByType[r.type] = r; });

  const systemPrompt = buildSystemPrompt(profile, memory, routinesByType);

  // Call Anthropic
  const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, system: systemPrompt, messages })
  });

  const anthropicData = await anthropicRes.json();
  const reply = anthropicData.content?.[0]?.text || 'Something went wrong.';

  // Save conversation to DB
  const lastUserMessage = messages[messages.length - 1]?.content || '';
  await supabase.from('conversations').insert([
    { user_id: req.user.id, role: 'user', content: lastUserMessage },
    { user_id: req.user.id, role: 'assistant', content: reply }
  ]);

  // Fire background jobs
  const transcript = [...messages, { role: 'assistant', content: reply }]
    .map(m => `${m.role === 'user' ? (profile?.name || 'User') : 'Coach'}: ${m.content}`)
    .join('\n');
  runBackgroundJobs(req.user.id, reply, transcript);

  res.json({ reply });
});

// ── Background jobs ────────────────────────────────────────────────────────
async function runBackgroundJobs(userId, reply, transcript) {
  await Promise.allSettled([
    extractAndSaveMemory(userId, transcript),
    extractAndSaveRoutines(userId, reply)
  ]);
}

async function callClaude(prompt, maxTokens = 300) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] })
  });
  const data = await res.json();
  return data.content?.[0]?.text?.replace(/```json|```/g, '').trim() || '';
}

async function extractAndSaveMemory(userId, transcript) {
  const prompt = `Extract NEW facts from this coaching conversation worth remembering about the user. Only genuinely new info.
Examples: new PRs, injuries, diet changes, goal shifts, mood/energy, life context.
JSON only: {"facts":["..."]} or {"facts":[]}. No preamble, no markdown.

TRANSCRIPT:
${transcript}`;
  try {
    const raw = await callClaude(prompt, 300);
    const { facts } = JSON.parse(raw);
    if (facts?.length) {
      const date = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      await supabase.from('memory_log').insert(facts.map(text => ({ user_id: userId, text, date })));
    }
  } catch(e) {}
}

async function extractAndSaveRoutines(userId, reply) {
  if (!/workout|meal plan|diet plan|sleep|routine|schedule|monday|tuesday|wednesday|sets|reps|cardio|breakfast|lunch|dinner/i.test(reply)) return;
  const prompt = `Extract structured routine data from this coach message.
Format (only include keys present):
{"workout":{"sections":[{"title":"Day/focus","items":["Exercise sets/reps"]}]},
 "diet":{"sections":[{"title":"Category","items":["Meal"]}]},
 "sleep":{"sections":[{"title":"Schedule","items":["Time/habit"]}]}}
If no routine: {}. JSON only, no markdown.

MESSAGE:
${reply}`;
  try {
    const raw = await callClaude(prompt, 800);
    const parsed = JSON.parse(raw);
    const date = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    for (const [type, val] of Object.entries(parsed)) {
      if (val?.sections?.length) {
        await supabase.from('routines')
          .upsert({ user_id: userId, type, sections: val.sections, source: 'coach', updated_at: date },
                  { onConflict: 'user_id,type' });
      }
    }
  } catch(e) {}
}

// ── System prompt builder ──────────────────────────────────────────────────
function buildSystemPrompt(profile, memory, routines) {
  if (!profile) return 'You are a personal coach. Ask the user to complete their profile setup.';

  const h = parseInt(profile.height), ft = Math.floor(h/12), inch = h%12;
  const memBlock = memory.length
    ? '\nMEMORY LOG:\n' + memory.map(m => `- [${m.date}] ${m.text}`).join('\n') : '';
  const routineBlock = Object.keys(routines).length
    ? '\nCURRENT ROUTINES:\n' + Object.entries(routines).map(([k,r]) =>
        `${k.toUpperCase()} (updated ${r.updated_at}):\n` +
        r.sections.map(s => `  ${s.title}:\n${s.items.map(i => `    - ${i}`).join('\n')}`).join('\n')
      ).join('\n\n') : '';

  return `You are a sharp, direct, and knowledgeable personal coach. NOT a generic AI — this person's dedicated coach with full context.

USER PROFILE:
- Name: ${profile.name} | Age: ${profile.age} | Sex: ${profile.sex}
- Weight: ${profile.weight} lbs | Height: ${ft}′${inch}″
- Goal: ${profile.goal} | Diet: ${profile.diet}
- Injuries: ${profile.injuries} | Trains: ${profile.freq}/week
- Notes: ${profile.notes || 'None'}
${memBlock}${routineBlock}

COACHING STYLE:
- Direct and specific. No filler. No generic advice.
- Always factor in profile, memory, and current routines.
- Concise but substantive. Short paragraphs or brief lists.
- Smart adult tone. No hand-holding.
- Suggest next steps when relevant.

BANNED PHRASES (never use):
"I'll be honest", "Here's the reality", "Let's be real", "Real talk", "I have to say",
"At the end of the day", "The truth is", "Look," as opener, any confession/revelation framing.
Just say the thing. No wind-up.`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Coach backend running on port ${PORT}`));
