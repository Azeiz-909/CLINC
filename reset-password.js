// POST /api/reset-password
// Admin-only: generates a new temporary password for an existing staff
// account and forces them to set their own password again at next login.
const { createClient } = require('@supabase/supabase-js');

function genTempPassword(){
  const letters = Math.random().toString(36).slice(2, 6).toUpperCase();
  const digits = String(Math.floor(1000 + Math.random() * 9000));
  return 'T' + letters + digits;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }

  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) { res.status(401).json({ error: 'مطلوب تسجيل الدخول' }); return; }

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!supabaseUrl || !serviceKey) {
      res.status(500).json({ error: 'إعداد الخادم غير مكتمل — تحقق من متغيرات البيئة' });
      return;
    }
    const admin = createClient(supabaseUrl, serviceKey);

    const { data: userData, error: userErr } = await admin.auth.getUser(token);
    if (userErr || !userData || !userData.user) { res.status(401).json({ error: 'جلسة غير صالحة' }); return; }
    const callerId = userData.user.id;

    const { data: callerProfile } = await admin.from('profiles').select('role').eq('id', callerId).single();
    if (!callerProfile || callerProfile.role !== 'admin') {
      res.status(403).json({ error: 'هذا الإجراء متاح للمدير فقط' });
      return;
    }

    const { userId } = req.body || {};
    if (!userId) { res.status(400).json({ error: 'معرّف الحساب مطلوب' }); return; }

    const tempPassword = genTempPassword();
    const { error: updErr } = await admin.auth.admin.updateUserById(userId, { password: tempPassword });
    if (updErr) { res.status(400).json({ error: updErr.message || 'تعذر إعادة تعيين كلمة المرور' }); return; }

    await admin.from('profiles').update({ must_change_password: true }).eq('id', userId);

    res.status(200).json({ tempPassword });
  } catch (e) {
    res.status(500).json({ error: 'خطأ غير متوقع في الخادم' });
  }
};
