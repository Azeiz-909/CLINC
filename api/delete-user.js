// POST /api/delete-user
// Admin-only: permanently deletes a staff account (auth user + profile row).
const { createClient } = require('@supabase/supabase-js');

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
    if (userId === callerId) { res.status(400).json({ error: 'لا يمكنك حذف حسابك الخاص' }); return; }

    // منع حذف آخر حساب مدير في النظام
    const { data: admins } = await admin.from('profiles').select('id').eq('role', 'admin');
    if (admins && admins.length <= 1 && admins[0].id === userId) {
      res.status(400).json({ error: 'لا يمكن حذف آخر حساب مدير في النظام' });
      return;
    }

    // profiles تُحذف تلقائيًا عبر (on delete cascade) عند حذف حساب المصادقة
    const { error: delErr } = await admin.auth.admin.deleteUser(userId);
    if (delErr) { res.status(400).json({ error: delErr.message || 'تعذر حذف الحساب' }); return; }

    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'خطأ غير متوقع في الخادم' });
  }
};
