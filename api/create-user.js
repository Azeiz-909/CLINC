// POST /api/create-user
// Admin-only: creates a new staff account with a temporary password.
// Must run on the server (Vercel serverless function) because it needs
// the SUPABASE_SERVICE_ROLE_KEY, which must never reach the browser.
const { createClient } = require('@supabase/supabase-js');

function genTempPassword(){
  const letters = Math.random().toString(36).slice(2, 6).toUpperCase();
  const digits = String(Math.floor(1000 + Math.random() * 9000));
  return 'T' + letters + digits; // e.g. "TQ7X4821"
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

    // تحقق من هوية المستخدم صاحب الطلب
    const { data: userData, error: userErr } = await admin.auth.getUser(token);
    if (userErr || !userData || !userData.user) { res.status(401).json({ error: 'جلسة غير صالحة' }); return; }
    const callerId = userData.user.id;

    // تحقق أنه "admin"
    const { data: callerProfile } = await admin.from('profiles').select('role').eq('id', callerId).single();
    if (!callerProfile || callerProfile.role !== 'admin') {
      res.status(403).json({ error: 'هذا الإجراء متاح للمدير فقط' });
      return;
    }

    const { username, name, tempPassword: customTempPassword } = req.body || {};
    if (!username || !name) { res.status(400).json({ error: 'الاسم واسم المستخدم مطلوبان' }); return; }
    if (customTempPassword && String(customTempPassword).length < 6) {
      res.status(400).json({ error: 'الرمز المؤقت يجب أن يكون ٦ أحرف على الأقل' });
      return;
    }

    const cleanUsername = String(username).trim().toLowerCase().replace(/[^a-z0-9_.]/g, '');
    if (!cleanUsername) {
      res.status(400).json({ error: 'اسم مستخدم غير صالح — استخدم حروفًا إنجليزية أو أرقامًا فقط' });
      return;
    }
    const fakeEmail = `${cleanUsername}@clinic.internal`;
    // يستخدم الرمز اللي كتبه المدير يدويًا إن وُجد، وإلا يولّد واحدًا عشوائيًا
    const tempPassword = customTempPassword ? String(customTempPassword) : genTempPassword();

    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email: fakeEmail,
      password: tempPassword,
      email_confirm: true
    });
    if (createErr) {
      const msg = /already registered|already exists/i.test(createErr.message || '')
        ? 'اسم المستخدم هذا مستخدم بالفعل'
        : (createErr.message || 'تعذر إنشاء الحساب');
      res.status(400).json({ error: msg });
      return;
    }

    const { error: profileErr } = await admin.from('profiles').insert({
      id: created.user.id,
      username: cleanUsername,
      name: String(name).trim(),
      role: 'staff',
      must_change_password: true
    });
    if (profileErr) {
      // نظّف حساب المصادقة إن فشل إنشاء الملف الشخصي حتى لا يبقى حساب "يتيم"
      await admin.auth.admin.deleteUser(created.user.id).catch(() => {});
      res.status(400).json({ error: profileErr.message || 'تعذر إنشاء الملف الشخصي' });
      return;
    }

    res.status(200).json({ username: cleanUsername, tempPassword });
  } catch (e) {
    res.status(500).json({ error: 'خطأ غير متوقع في الخادم' });
  }
};
