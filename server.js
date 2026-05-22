require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const sessions = new Map();
function generateToken() { return crypto.randomBytes(32).toString('hex'); }

// ── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  const userId = sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'Invalid or expired session' });
  req.userId = userId;
  next();
}

// ── Health check ───────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'Coach backend running' }));

// ── Auth ───────────────────────────────────────────────────────────────────
app.post('/auth/signup', async (req, res) => {
  const { username, pin } = req.body;
  if (!username || !pin) return res.status(400).json({ error: 'Username and PIN required' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 4 digits' });
  if (username.length < 2) return res.status(400).json({ error: 'Username too short' });

  const { data: existing } = await supabase.from('users').select('id').eq('username', username.toLowerCase()).single();
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const pin_hash = await bcrypt.hash(pin, 10);
  const { data, error } = await supabase.from('users').insert({ username: username.toLowerCase(), pin_hash }).select().single();
  if (error) { console.error('Signup error:', error); return res.status(500).json({ error: 'Failed to create account' }); }

  const token = generateToken();
  sessions.set(token, data.id);
  res.json({ token, userId: data.id, username: data.username });
});

app.post('/auth/signin', async (req, res) => {
  const { username, pin } = req.body;
  if (!username || !pin) return res.status(400).json({ error: 'Username and PIN required' });

  const { data: user, error } = await supabase.from('users').select('*').eq('username', username.toLowerCase()).single();
  if (error || !user) return res.status(401).json({ error: 'Username not found' });

  const valid = await bcrypt.compare(pin, user.pin_hash);
  if (!valid) return res.status(401).json({ error: 'Wrong PIN' });

  // Check session thresholds before updating last_seen
  const { data: profile } = await supabase.from('profiles').select('last_seen, last_checkin, onboarding_complete').eq('id', user.id).single();
  const now = Date.now();
  const lastSeen = profile?.last_seen ? new Date(profile.last_seen) : null;
  const lastCheckin = profile?.last_checkin ? new Date(profile.last_checkin) : null;
  const minutesSinceSeen = lastSeen ? (now - lastSeen.getTime()) / (1000 * 60) : null;
  const hoursSinceCheckin = lastCheckin ? (now - lastCheckin.getTime()) / (1000 * 60 * 60) : null;
  const needsOnboarding = profile && !profile.onboarding_complete;

  const flaggedItems = await getFlaggedItems(user.id, profile?.last_seen);

  let openerType = null;
  if (flaggedItems.length > 0) {
    openerType = 'checkin';
  } else if (hoursSinceCheckin === null || hoursSinceCheckin >= 6) {
    openerType = 'checkin';
  } else if (minutesSinceSeen === null || minutesSinceSeen >= 30) {
    openerType = 'greeting';
  }

  const token = generateToken();
  sessions.set(token, user.id);
  res.json({ token, userId: user.id, username: user.username, openerType, needsOnboarding, flaggedItems });
});

app.post('/auth/signout', requireAuth, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  // Update last_seen on signout
  await supabase.from('profiles').update({ last_seen: new Date().toISOString() }).eq('id', req.userId);
  sessions.delete(token);
  res.json({ success: true });
});

// ── Heartbeat — keeps last_seen current while app is open ──────────────────
app.post('/heartbeat', requireAuth, async (req, res) => {
  await supabase.from('profiles').update({ last_seen: new Date().toISOString() }).eq('id', req.userId);
  res.json({ ok: true });
});

// ── Session opener — generates Coach's first message ──────────────────────
app.get('/session-opener', requireAuth, async (req, res) => {
  const { type, flagged } = req.query; // 'onboarding', 'checkin', or 'greeting'

  const [profileRes, memoryRes, routinesRes] = await Promise.all([
    supabase.from('profiles').select('*').eq('id', req.userId).single(),
    supabase.from('memory_log').select('*').eq('user_id', req.userId).order('created_at', { ascending: false }).limit(10),
    supabase.from('routines').select('*').eq('user_id', req.userId)
  ]);

  const profile = profileRes.data;
  const memory = memoryRes.data || [];
  const routines = routinesRes.data || [];

  const timeOfDay = (() => {
    const h = new Date().getHours();
    if (h < 12) return 'morning';
    if (h < 17) return 'afternoon';
    return 'evening';
  })();

  let prompt;

  if (type === 'greeting') {
    const recentMemory = memory.slice(0, 2).map(m => '- ' + m.text).join('\n') || 'Nothing recent';
    prompt = `You are Coach, a personal AI coach. The user just opened the app after a short break (30+ minutes but less than 6 hours).

USER: ${profile.name} | Goal: ${profile.goal} | Time of day: ${timeOfDay}
RECENT MEMORY:
${recentMemory}

Write a brief warm greeting under 30 words. Vary your style — sometimes just acknowledge them, sometimes ask something light and casual like how they're feeling or how their day is going. Don't ask about workout or diet specifically — save that for full check-ins. Natural, not robotic.
BANNED: "I'll be honest", "Here's the reality", filler openers.`;

  } else if (type === 'onboarding') {
    prompt = `You are Coach, a personal AI coach. A new user just completed their profile setup. Write a warm, direct intro message to kick off your first conversation with them.

USER PROFILE:
- Name: ${profile.name} | Age: ${profile.age} | Sex: ${profile.sex}
- Weight: ${profile.weight} lbs | Goal: ${profile.goal}
- Diet: ${profile.diet} | Trains: ${profile.freq}/week
- Injuries: ${profile.injuries}
- Notes: ${profile.notes || 'None'}

Write a message that:
1. Introduces yourself briefly as Coach (not as an AI)
2. Acknowledges one specific thing from their profile (goal or situation)
3. Asks 2 short questions to get to know them better — pick from: where they train, how long they've been training, what's worked/not worked before, what's driving them right now, how much time per session, do they track macros
4. Keep it conversational and under 80 words
5. Do NOT use "I'll be honest", "Here's the reality", or any filler openers`;

  } else {
    // Check-in — gap-aware, targets uncovered topics first
    const today = new Date().toLocaleDateString('en-US', { weekday: 'long' });
    const routineNames = routines.map(r => r.type).join(', ');
    const memoryText = memory.map(m => m.text.toLowerCase()).join(' ');

    const topics = [
      { key: 'diet', keywords: ['breakfast', 'lunch', 'dinner', 'eat', 'food', 'macro', 'calori', 'diet', 'meal', 'nutrition'], question: 'Ask one focused question about their typical daily eating habits or how they approach nutrition.' },
      { key: 'history', keywords: ['year', 'been training', 'started', 'experience', 'background', 'worked before', 'used to'], question: 'Ask one focused question about their training background — how long they have been training or what has worked for them before.' },
      { key: 'schedule', keywords: ['morning', 'evening', 'time', 'schedule', 'busy', 'work', 'sleep', 'night', 'routine'], question: 'Ask one focused question about their daily schedule — when they prefer to train or what their typical day looks like.' },
      { key: 'motivation', keywords: ['motivat', 'goal', 'driving', 'why', 'event', 'deadline', 'reason'], question: 'Ask one focused question about what is driving them right now — what they are chasing or why this goal matters to them.' },
      { key: 'equipment', keywords: ['gym', 'home', 'equipment', 'dumbbell', 'barbell', 'machine', 'train at'], question: 'Ask one focused question about where they train and what equipment they have access to.' },
    ];

    const uncovered = topics.find(t => !t.keywords.some(k => memoryText.includes(k)));

    let parsedFlagged = [];
    try { parsedFlagged = flagged ? JSON.parse(decodeURIComponent(flagged)) : []; } catch(e) {}

    let focusInstruction;
    if (parsedFlagged.length > 0) {
      const f = parsedFlagged[0];
      const dayName = f.day.charAt(0).toUpperCase() + f.day.slice(1);
      focusInstruction = `The user had a ${f.routine_type} session scheduled for ${dayName} (${f.section_title}) that passed since they last used the app. Ask how it went — naturally, not like a system check.`;
    } else if (uncovered) {
      focusInstruction = uncovered.question;
    } else {
      focusInstruction = 'Ask one focused question based on their recent activity or progress toward their goal.';
    }

    const recentMemory = memory.slice(0, 3).map(m => '- ' + m.text).join('\n') || 'Nothing recent';

    prompt = `You are Coach, a personal AI coach. This user is returning after more than 6 hours away. Open the conversation proactively with a check-in message.

USER PROFILE:
- Name: ${profile.name} | Goal: ${profile.goal} | Trains: ${profile.freq}/week

TODAY: ${today}
ACTIVE ROUTINES: ${routineNames || 'None yet'}
RECENT MEMORY:
${recentMemory}

Write a check-in message that:
1. Feels natural, not robotic — like a coach who has been thinking about their client
2. Optionally references something specific from memory or routines if relevant
3. ${focusInstruction}
4. Keep it under 70 words
5. Do NOT use "I will be honest", "Here is the reality", or filler openers
6. Do NOT start with "Hey" or "Hi ${profile.name}" every time — vary the opener`;
  }

  try {
    const raw = await callClaude(prompt, 300);
    // Save opener to conversations (not for greetings — keep those light)
    if (type !== 'greeting') {
      await supabase.from('conversations').insert({ user_id: req.userId, role: 'assistant', content: raw });
    }
    // Update timestamps
    if (type === 'onboarding') {
      await supabase.from('profiles').update({ onboarding_complete: true, last_seen: new Date().toISOString() }).eq('id', req.userId);
    } else if (type === 'checkin') {
      await supabase.from('profiles').update({ last_checkin: new Date().toISOString() }).eq('id', req.userId);
    }
    res.json({ message: raw });
  } catch(e) {
    console.error('Session opener error:', e);
    res.status(500).json({ error: 'Failed to generate opener' });
  }
});

// ── Session status — for returning users with stored token ─────────────────
app.get('/session-status', requireAuth, async (req, res) => {
  const { data: profile } = await supabase
    .from('profiles')
    .select('last_seen, last_checkin, onboarding_complete')
    .eq('id', req.userId)
    .single();

  const now = Date.now();
  const lastSeen = profile?.last_seen ? new Date(profile.last_seen) : null;
  const lastCheckin = profile?.last_checkin ? new Date(profile.last_checkin) : null;

  const minutesSinceSeen = lastSeen ? (now - lastSeen.getTime()) / (1000 * 60) : null;
  const hoursSinceCheckin = lastCheckin ? (now - lastCheckin.getTime()) / (1000 * 60 * 60) : null;

  // Flagged compliance items always take priority
  const flaggedItems = await getFlaggedItems(req.userId, profile?.last_seen);

  let openerType = null;
  if (flaggedItems.length > 0) {
    openerType = 'checkin'; // compliance flag — full check-in
  } else if (hoursSinceCheckin === null || hoursSinceCheckin >= 6) {
    openerType = 'checkin'; // 6+ hours since last full check-in
  } else if (minutesSinceSeen === null || minutesSinceSeen >= 30) {
    openerType = 'greeting'; // 30+ minutes — warm greeting
  }

  res.json({ openerType, flaggedItems });
});

// ── Profile ────────────────────────────────────────────────────────────────
app.get('/profile', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('profiles').select('*').eq('id', req.userId).single();
  if (error && error.code !== 'PGRST116') return res.status(500).json({ error });
  res.json(data || null);
});

app.post('/profile', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('profiles').upsert({ id: req.userId, ...req.body }).select().single();
  if (error) { console.error('Profile upsert error:', error); return res.status(500).json({ error }); }
  res.json(data);
});

// ── Memory log ─────────────────────────────────────────────────────────────
app.get('/memory', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('memory_log').select('*').eq('user_id', req.userId).order('created_at', { ascending: false }).limit(40);
  if (error) return res.status(500).json({ error });
  res.json(data || []);
});

// ── Permanent memory ──────────────────────────────────────────────────────
app.get('/memory/permanent', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('memory_permanent')
    .select('*')
    .eq('user_id', req.userId)
    .order('updated_at', { ascending: false });
  if (error) return res.status(500).json({ error });
  res.json(data || []);
});

// ── Routines ───────────────────────────────────────────────────────────────
app.get('/routines', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('routines').select('*').eq('user_id', req.userId);
  if (error) return res.status(500).json({ error });
  const result = {};
  (data || []).forEach(r => { result[r.type] = { sections: r.sections, source: r.source, updatedAt: r.updated_at }; });
  res.json(result);
});

app.post('/routines', requireAuth, async (req, res) => {
  const { type, sections, source } = req.body;
  const updated_at = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const { data, error } = await supabase.from('routines')
    .upsert({ user_id: req.userId, type, sections, source: source || 'coach', updated_at }, { onConflict: 'user_id,type' })
    .select().single();
  if (error) { console.error('Routine upsert error:', error); return res.status(500).json({ error }); }
  res.json(data);
});

app.delete('/routines/:type', requireAuth, async (req, res) => {
  const { error } = await supabase.from('routines').delete().eq('user_id', req.userId).eq('type', req.params.type);
  if (error) return res.status(500).json({ error });
  res.json({ success: true });
});

// ── Conversations ──────────────────────────────────────────────────────────
app.get('/conversations', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('conversations').select('*').eq('user_id', req.userId).order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error });
  res.json(data || []);
});

// ── Chat ───────────────────────────────────────────────────────────────────
app.post('/chat', requireAuth, async (req, res) => {
  const { messages } = req.body;
  if (!messages?.length) return res.status(400).json({ error: 'No messages' });

  const [profileRes, memoryRes, permanentMemRes, routinesRes, complianceStr] = await Promise.all([
    supabase.from('profiles').select('*').eq('id', req.userId).single(),
    supabase.from('memory_log').select('*').eq('user_id', req.userId).order('created_at', { ascending: false }).limit(40),
    supabase.from('memory_permanent').select('*').eq('user_id', req.userId).order('updated_at', { ascending: false }),
    supabase.from('routines').select('*').eq('user_id', req.userId),
    getComplianceSummary(req.userId)
  ]);

  const profile = profileRes.data;
  const memory = memoryRes.data || [];
  const permanentMemory = permanentMemRes.data || [];
  const routinesByType = {};
  (routinesRes.data || []).forEach(r => { routinesByType[r.type] = r; });

  const systemPrompt = buildSystemPrompt(profile, memory, permanentMemory, routinesByType, complianceStr);

  const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, system: systemPrompt, messages })
  });

  const anthropicData = await anthropicRes.json();
  const reply = anthropicData.content?.[0]?.text || 'Something went wrong.';

  const lastUserMessage = messages[messages.length - 1]?.content || '';
  await supabase.from('conversations').insert([
    { user_id: req.userId, role: 'user', content: lastUserMessage },
    { user_id: req.userId, role: 'assistant', content: reply }
  ]);

  const transcript = [...messages, { role: 'assistant', content: reply }]
    .map(m => `${m.role === 'user' ? (profile?.name || 'User') : 'Coach'}: ${m.content}`).join('\n');
  runBackgroundJobs(req.userId, reply, transcript);

  // Clear pending conflict now that it's been surfaced
  if (profile?.pending_conflict) {
    await supabase.from('profiles').update({ pending_conflict: null }).eq('id', req.userId);
  }

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
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] })
  });
  const data = await res.json();
  return data.content?.[0]?.text?.replace(/```json|```/g, '').trim() || '';
}

async function extractAndSaveMemory(userId, transcript) {
  // Load existing permanent memory for conflict detection
  const { data: existingPermanent } = await supabase
    .from('memory_permanent').select('*').eq('user_id', userId);
  const permanentContext = (existingPermanent || [])
    .map(m => `- [${m.category}] ${m.text}`).join('\n') || 'None yet';

  const prompt = `Extract NEW facts from this coaching conversation worth remembering. Classify each as permanent or ephemeral.

PERMANENT facts (injuries, goal shifts, training history, equipment, strong preferences — things that define the person long-term):
- Return as: {"category": "injury|goal|history|equipment|preference", "text": "concise fact"}

EPHEMERAL facts (mood, energy, recent sessions, temporary context — things that matter now but not forever):
- Return as: {"text": "concise fact"}

EXISTING PERMANENT MEMORY (for conflict detection):
${permanentContext}

CONFLICT DETECTION: If a new permanent fact contradicts an existing one, flag it.
Example: existing says "goal: build muscle" but conversation reveals "started a cut" → flag this conflict.

Return ONLY valid JSON:
{
  "permanent": [{"category": "...", "text": "..."}],
  "ephemeral": [{"text": "..."}],
  "conflicts": [{"existing": "existing fact text", "new": "new contradicting fact", "category": "category"}]
}
If nothing new: {"permanent": [], "ephemeral": [], "conflicts": []}
No preamble, no markdown.

TRANSCRIPT:
${transcript}`;

  try {
    const raw = await callClaude(prompt, 500);
    const parsed = JSON.parse(raw);
    const date = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

    // Save ephemeral facts
    if (parsed.ephemeral?.length) {
      await supabase.from('memory_log').insert(
        parsed.ephemeral.map(f => ({ user_id: userId, text: f.text, date }))
      );
      const { data: all } = await supabase.from('memory_log').select('id').eq('user_id', userId).order('created_at', { ascending: false });
      if (all && all.length > 40) await supabase.from('memory_log').delete().in('id', all.slice(40).map(r => r.id));
    }

    // Save permanent facts (upsert by user_id + category + text)
    if (parsed.permanent?.length) {
      for (const fact of parsed.permanent) {
        if (!fact.category || !fact.text) continue;
        await supabase.from('memory_permanent')
          .upsert(
            { user_id: userId, category: fact.category, text: fact.text, updated_at: new Date().toISOString() },
            { onConflict: 'user_id,category,text' }
          );
      }
    }

    // Store conflicts for next reply (save to a temp conflicts table via profile jsonb)
    if (parsed.conflicts?.length) {
      await supabase.from('profiles')
        .update({ pending_conflict: JSON.stringify(parsed.conflicts[0]) })
        .eq('id', userId);
    }

  } catch(e) { console.error('Memory extraction error:', e); }
}

async function extractAndSaveRoutines(userId, reply) {
  if (!/workout|meal plan|diet plan|sleep|routine|schedule|monday|tuesday|wednesday|sets|reps|cardio|breakfast|lunch|dinner/i.test(reply)) return;
  const prompt = `Extract structured routine data from this coach message.

CRITICAL TITLE FORMAT RULES:
- Workout sections MUST use day names: "Monday — Push", "Wednesday — Circuit", "Friday — Legs"
- Diet sections with specific days MUST use: "Sunday — Meal Prep", "Monday-Friday — Lunch", "Daily — Breakfast"
- Diet sections without specific days use category: "Breakfast", "Lunch", "Dinner", "Snacks"
- Sleep sections use: "Schedule", "Wind-down Routine"
- Always include the day name in the title if a specific day or range is mentioned

Format (only include keys present):
{"workout":{"sections":[{"title":"Monday — Push","items":["Bench press 4x8","OHP 3x10"]}]},
 "diet":{"sections":[{"title":"Sunday — Meal Prep","items":["90 min burrito bowl prep"]},{"title":"Monday-Friday — Lunch","items":["Burrito bowl"]}]},
 "sleep":{"sections":[{"title":"Schedule","items":["Lights out 10:30pm","Wake 6:30am"]}]}}
If no routine: {}. JSON only, no markdown.

MESSAGE:
${reply}`;
  try {
    const raw = await callClaude(prompt, 800);
    const parsed = JSON.parse(raw);
    if (!Object.keys(parsed).length) return;
    const date = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    for (const [type, val] of Object.entries(parsed)) {
      if (val?.sections?.length) {
        const { error } = await supabase.from('routines')
          .upsert({ user_id: userId, type, sections: val.sections, source: 'coach', updated_at: date }, { onConflict: 'user_id,type' });
        if (error) console.error(`Routine save error (${type}):`, error);
        else console.log(`Routine saved: ${type}`);
      }
    }
  } catch(e) { console.error('Routine extraction error:', e); }
}

// ── System prompt ──────────────────────────────────────────────────────────
function buildSystemPrompt(profile, memory, permanentMemory, routines, complianceStr = '') {
  if (!profile) return 'You are a personal coach. Ask the user to complete their profile setup.';
  const h = parseInt(profile.height), ft = Math.floor(h/12), inch = h%12;
  const CATEGORY_LABELS = { injury: 'Injury', goal: 'Goal', history: 'History', equipment: 'Equipment', preference: 'Preference' };

  const permBlock = permanentMemory && permanentMemory.length
    ? '\nPERMANENT CONTEXT:\n' + permanentMemory.map(m => '- [' + (CATEGORY_LABELS[m.category] || m.category) + '] ' + m.text).join('\n') : '';

  const memBlock = memory.length
    ? '\nRECENT OBSERVATIONS:\n' + memory.map(m => '- [' + m.date + '] ' + m.text).join('\n') : '';

  const routineBlock = Object.keys(routines).length
    ? '\nCURRENT ROUTINES:\n' + Object.entries(routines).map(([k,r]) =>
        k.toUpperCase() + ' (updated ' + r.updated_at + '):\n' + r.sections.map(s => '  ' + s.title + ':\n' + s.items.map(i => '    - ' + i).join('\n')).join('\n')
      ).join('\n\n') : '';

  let conflictBlock = '';
  if (profile.pending_conflict) {
    try {
      const c = typeof profile.pending_conflict === 'string'
        ? JSON.parse(profile.pending_conflict) : profile.pending_conflict;
      conflictBlock = '\nPENDING CONFLICT TO SURFACE: Before or after answering, naturally ask the user about this contradiction — keep it conversational, not like a system alert. Previously noted "' + c.existing + '" but recent conversation suggests "' + c.new + '". Ask if their ' + c.category + ' has changed.';
    } catch(e) {}
  }

  const now = new Date();
  const currentDate = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  return 'You are a sharp, direct, and knowledgeable personal coach. NOT a generic AI — this person\'s dedicated coach with full context.\n\n' +
    'TODAY: ' + currentDate + '\n\n' +
    'USER PROFILE:\n' +
    '- Name: ' + profile.name + ' | Age: ' + profile.age + ' | Sex: ' + profile.sex + '\n' +
    '- Weight: ' + profile.weight + ' lbs | Height: ' + ft + '\u2032' + inch + '\u2033\n' +
    '- Goal: ' + profile.goal + ' | Diet: ' + profile.diet + '\n' +
    '- Injuries: ' + profile.injuries + ' | Trains: ' + profile.freq + '/week\n' +
    '- Notes: ' + (profile.notes || 'None') +
    permBlock + memBlock + routineBlock + complianceStr + conflictBlock + '\n\n' +
    'APP FEATURES (you have access to these):\n' +
    '- Routines tab: stores the user\'s workout, meal, and sleep plans — you can create and update these directly\n' +
    '- Calendar tab: automatically populated from routines, shows daily planned items with completion tracking\n' +
    '- When the user asks to save something to the calendar or schedule something, save it as a routine and it will appear in their calendar automatically\n' +
    '- Never say you lack calendar access — you have full access through the routines system\n\n' +
    'COACHING STYLE:\n' +
    '- Direct and specific. No filler. No generic advice.\n' +
    '- Always factor in profile, permanent context, recent observations, and routines.\n' +
    '- Concise but substantive. Short paragraphs or brief lists.\n' +
    '- Smart adult tone. No hand-holding.\n' +
    '- Suggest next steps when relevant.\n\n' +
    'BANNED PHRASES (never use):\n' +
    '"I\'ll be honest", "Here\'s the reality", "Let\'s be real", "Real talk", "I have to say",\n' +
    '"At the end of the day", "The truth is", "Look," as opener, any confession/revelation framing.\n' +
    'Just say the thing. No wind-up.';
}


// ── Completions ────────────────────────────────────────────────────────────

// Get completions for a date range
app.get('/completions', requireAuth, async (req, res) => {
  const { start, end } = req.query;
  let query = supabase.from('completions').select('*').eq('user_id', req.userId).order('date', { ascending: true });
  if (start) query = query.gte('date', start);
  if (end) query = query.lte('date', end);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error });
  res.json(data || []);
});

// Upsert a completion
app.post('/completions', requireAuth, async (req, res) => {
  const { date, routine_type, section_title, status, note } = req.body;
  if (!date || !routine_type || !section_title) return res.status(400).json({ error: 'Missing required fields' });
  const { data, error } = await supabase
    .from('completions')
    .upsert(
      { user_id: req.userId, date, routine_type, section_title, status: status || 'pending', note: note || null },
      { onConflict: 'user_id,date,routine_type,section_title' }
    )
    .select().single();
  if (error) { console.error('Completion upsert error:', error); return res.status(500).json({ error }); }
  res.json(data);
});

// Get compliance summary for system prompt (last 7 days)
async function getComplianceSummary(userId) {
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - 7);
  const { data } = await supabase
    .from('completions')
    .select('*')
    .eq('user_id', userId)
    .gte('date', start.toISOString().split('T')[0])
    .lte('date', end.toISOString().split('T')[0])
    .order('date', { ascending: false });
  if (!data || !data.length) return '';
  const lines = data.map(c => {
    const day = new Date(c.date + 'T12:00:00').toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    const icon = c.status === 'completed' ? 'completed' : c.status === 'skipped' ? 'skipped' : 'pending';
    const note = c.note ? ' (' + c.note + ')' : '';
    return '- ' + day + ' ' + c.routine_type + ': ' + icon + note;
  });
  return '\nCOMPLIANCE LOG (last 7 days):\n' + lines.join('\n');
}

// Check for flagged items since last_seen
async function getFlaggedItems(userId, lastSeen) {
  if (!lastSeen) return [];
  const { data: routines } = await supabase.from('routines').select('*').eq('user_id', userId);
  if (!routines || !routines.length) return [];
  const now = new Date();
  const last = new Date(lastSeen);
  const flagged = [];
  const days = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday'];
  for (const routine of routines) {
    for (const section of (routine.sections || [])) {
      const titleLower = section.title.toLowerCase();
      const dayMatch = days.find(d => titleLower.includes(d));
      if (!dayMatch) continue;
      const dayIndex = days.indexOf(dayMatch);
      const check = new Date(now);
      while (check.getDay() !== dayIndex) check.setDate(check.getDate() - 1);
      if (check > last && check <= now) {
        const dateStr = check.toISOString().split('T')[0];
        const { data: existing } = await supabase
          .from('completions').select('id')
          .eq('user_id', userId).eq('date', dateStr)
          .eq('routine_type', routine.type).eq('section_title', section.title)
          .single();
        if (!existing) {
          flagged.push({ date: dateStr, day: dayMatch, routine_type: routine.type, section_title: section.title });
        }
      }
    }
  }
  return flagged;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Coach backend running on port ${PORT}`));
