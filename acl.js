export default function acl(req, res, next) {
  const publicPaths = ['/', '/health', '/api/auth/register', '/api/auth/login'];
  if (publicPaths.includes(req.path) || req.path.startsWith('/api/public')) return next();
  if (!req.session) return res.status(500).json({ error: 'Session middleware required' });
  if (!req.session.user) {
    if (req.method === 'GET') return next();
    return res.status(401).json({ error: 'Authentication required' });
  }
  const role = req.session.user.role || 'member';
  req.userRole = role;
  req.userId = req.session.user.id;
  req.isAdmin = () => role === 'administrator';
  req.isModerator = () => role === 'moderator' || req.isAdmin();
  req.isOwner = (ownerId) => String(ownerId) === String(req.userId);
  return next();
}
