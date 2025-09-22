import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';

// Utility to pick safe fields
const toSafeUser = (u) => ({ id: u.id, email: u.email, role: u.role, tenantId: u.tenantId });

// Health endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id, tenantId: user.tenantId, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: toSafeUser(user) });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Auth middleware
function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  const [, token] = auth.split(' ');
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { userId, tenantId, role }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// Notes CRUD (tenant isolated)
app.post('/notes', authenticate, async (req, res) => {
  try {
    const { title, content } = req.body || {};
    if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });

    // Enforce plan limits
    const tenant = await prisma.tenant.findUnique({ where: { id: req.user.tenantId } });
    if (!tenant) return res.status(404).json({ error: 'Tenant not found' });
    if (tenant.plan === 'FREE') {
      const count = await prisma.note.count({ where: { tenantId: tenant.id } });
      if (count >= 3) return res.status(402).json({ error: 'FREE plan limit reached. Upgrade to PRO.' });
    }

    const note = await prisma.note.create({
      data: {
        title,
        content,
        tenantId: req.user.tenantId,
        ownerId: req.user.userId,
      },
    });
    res.status(201).json(note);
  } catch (err) {
    console.error('Create note error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/notes', authenticate, async (req, res) => {
  try {
    const notes = await prisma.note.findMany({ where: { tenantId: req.user.tenantId }, orderBy: { createdAt: 'desc' } });
    res.json(notes);
  } catch (err) {
    console.error('List notes error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/notes/:id', authenticate, async (req, res) => {
  try {
    const note = await prisma.note.findFirst({ where: { id: req.params.id, tenantId: req.user.tenantId } });
    if (!note) return res.status(404).json({ error: 'Not found' });
    res.json(note);
  } catch (err) {
    console.error('Get note error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/notes/:id', authenticate, async (req, res) => {
  try {
    const { title, content } = req.body || {};
    const existing = await prisma.note.findFirst({ where: { id: req.params.id, tenantId: req.user.tenantId } });
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const updated = await prisma.note.update({ where: { id: existing.id }, data: { title, content } });
    res.json(updated);
  } catch (err) {
    console.error('Update note error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/notes/:id', authenticate, async (req, res) => {
  try {
    const existing = await prisma.note.findFirst({ where: { id: req.params.id, tenantId: req.user.tenantId } });
    if (!existing) return res.status(404).json({ error: 'Not found' });
    await prisma.note.delete({ where: { id: existing.id } });
    res.status(204).send();
  } catch (err) {
    console.error('Delete note error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Upgrade endpoint (ADMIN only)
app.post('/tenants/:slug/upgrade', authenticate, requireRole('ADMIN'), async (req, res) => {
  try {
    const { slug } = req.params;
    const tenant = await prisma.tenant.findFirst({ where: { slug } });
    if (!tenant) return res.status(404).json({ error: 'Tenant not found' });
    if (tenant.id !== req.user.tenantId) return res.status(403).json({ error: 'Cannot upgrade another tenant' });
    if (tenant.plan === 'PRO') return res.json({ message: 'Already PRO', tenant });
    const updated = await prisma.tenant.update({ where: { id: tenant.id }, data: { plan: 'PRO' } });
    res.json({ message: 'Upgraded to PRO', tenant: updated });
  } catch (err) {
    console.error('Upgrade error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Local dev server, Vercel will use exported app
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

export default app;