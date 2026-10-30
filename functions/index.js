const {onCall, HttpsError} = require("firebase-functions/v2/https");
const {initializeApp} = require("firebase-admin/app");
const {getAuth} = require("firebase-admin/auth");
const {getFirestore, FieldValue, Timestamp} = require("firebase-admin/firestore");

initializeApp();
const db = getFirestore();
const auth = getAuth();

async function requireAdmin(req) {
  if (!req.auth) throw new HttpsError("unauthenticated", "Sign in required.");
  const snap = await db.doc(`admins/${req.auth.uid}`).get();
  if (!snap.exists) throw new HttpsError("permission-denied", "Admin access required.");
}
function requireUid(uid) {
  if (typeof uid !== "string" || !uid || uid.length > 128)
    throw new HttpsError("invalid-argument", "A valid uid is required.");
}
async function audit(actorUid, action, targetUid, details={}) {
  await db.collection("adminAudit").add({
    actorUid, action, targetUid: targetUid || null, details,
    createdAt: FieldValue.serverTimestamp()
  });
}
async function deleteUserTree(uid) {
  // Delete known user-owned documents. Extend this list if new subcollections are added.
  const notices = await db.collection(`userNotices/${uid}/items`).get();
  const batch = db.batch();
  notices.docs.forEach(d => batch.delete(d.ref));
  batch.delete(db.doc(`users/${uid}`));
  await batch.commit();
  await auth.deleteUser(uid);
}
exports.listUsers = onCall(async req => {
  await requireAdmin(req);
  const page = await auth.listUsers(100, req.data?.pageToken);
  const users = [];
  let active=0, blocked=0, verified=0;
  for (const u of page.users) {
    const p = await db.doc(`users/${u.uid}`).get();
    const profile = p.exists ? p.data() : {};
    if (u.disabled) blocked++; else active++;
    if (u.emailVerified) verified++;
    users.push({
      uid:u.uid, email:u.email||"", fullName:profile.fullName||"",
      username:profile.username||"", phone:profile.phone||"",
      disabled:u.disabled, emailVerified:u.emailVerified,
      createdAt:u.metadata.creationTime||null,
      lastSignInAt:u.metadata.lastSignInTime||null
    });
  }
  return {users, pageCount:users.length, active, blocked, verified,
    nextPageToken:page.pageToken||null};
});
exports.setUserBlocked = onCall(async req => {
  await requireAdmin(req);
  const {uid, blocked}=req.data||{}; requireUid(uid);
  if (typeof blocked!=="boolean") throw new HttpsError("invalid-argument","blocked must be boolean.");
  if (uid===req.auth.uid) throw new HttpsError("failed-precondition","You cannot block yourself.");
  await auth.updateUser(uid,{disabled:blocked});
  await db.doc(`users/${uid}`).set({blocked,updatedAt:FieldValue.serverTimestamp()},{merge:true});
  await audit(req.auth.uid, blocked?"USER_BLOCKED":"USER_UNBLOCKED",uid);
  return {ok:true};
});
exports.deleteUser = onCall(async req => {
  await requireAdmin(req);
  const {uid}=req.data||{}; requireUid(uid);
  if (uid===req.auth.uid) throw new HttpsError("failed-precondition","You cannot delete yourself.");
  await deleteUserTree(uid);
  await audit(req.auth.uid,"USER_DELETED",uid);
  return {ok:true};
});
exports.setNotice = onCall(async req => {
  await requireAdmin(req);
  const notice=String(req.data?.notice||"").slice(0,1500);
  await db.doc("settings/public").set({notice,updatedAt:FieldValue.serverTimestamp()},{merge:true});
  await audit(req.auth.uid,"NOTICE_UPDATED",null);
  return {ok:true};
});
exports.updateSiteSettings = onCall(async req => {
  await requireAdmin(req);
  const input=req.data||{};
  const allowed=["siteName","logoUrl","welcomeMessage","maintenanceMode","registrationEnabled","loginEnabled"];
  const update={updatedAt:FieldValue.serverTimestamp()};
  for (const k of allowed) {
    if (input[k]===undefined) continue;
    if (["maintenanceMode","registrationEnabled","loginEnabled"].includes(k) && typeof input[k]!=="boolean")
      throw new HttpsError("invalid-argument",`${k} must be boolean.`);
    if (["siteName","logoUrl","welcomeMessage"].includes(k)) update[k]=String(input[k]).slice(0,500);
    else update[k]=input[k];
  }
  await db.doc("settings/public").set(update,{merge:true});
  await audit(req.auth.uid,"SITE_SETTINGS_UPDATED",null,{keys:Object.keys(update)});
  return {ok:true};
});
exports.createAdmin = onCall(async req => {
  await requireAdmin(req);
  const {uid}=req.data||{}; requireUid(uid);
  if (uid===req.auth.uid) throw new HttpsError("failed-precondition","Already an admin.");
  await auth.getUser(uid);
  await db.doc(`admins/${uid}`).set({role:"admin",createdAt:FieldValue.serverTimestamp(),createdBy:req.auth.uid});
  await audit(req.auth.uid,"ADMIN_CREATED",uid);
  return {ok:true};
});
exports.removeAdmin = onCall(async req => {
  await requireAdmin(req);
  const {uid}=req.data||{}; requireUid(uid);
  if (uid===req.auth.uid) throw new HttpsError("failed-precondition","You cannot remove yourself.");
  await db.doc(`admins/${uid}`).delete();
  await audit(req.auth.uid,"ADMIN_REMOVED",uid);
  return {ok:true};
});
exports.sendUserNotice = onCall(async req => {
  await requireAdmin(req);
  const {uid,message}=req.data||{}; requireUid(uid);
  const body=String(message||"").trim().slice(0,1500);
  if (!body) throw new HttpsError("invalid-argument","Message is required.");
  await db.collection(`userNotices/${uid}/items`).add({
    message:body,read:false,createdAt:FieldValue.serverTimestamp()
  });
  await audit(req.auth.uid,"USER_NOTICE_SENT",uid);
  return {ok:true};
});
exports.revokeUserSessions = onCall(async req => {
  await requireAdmin(req);
  const {uid}=req.data||{}; requireUid(uid);
  await auth.revokeRefreshTokens(uid);
  await audit(req.auth.uid,"USER_SESSIONS_REVOKED",uid);
  return {ok:true};
});
exports.suspendUserUntil = onCall(async req => {
  await requireAdmin(req);
  const {uid,untilMillis}=req.data||{}; requireUid(uid);
  if (!Number.isFinite(untilMillis) || untilMillis<=Date.now())
    throw new HttpsError("invalid-argument","A future untilMillis is required.");
  await auth.updateUser(uid,{disabled:true});
  await db.doc(`users/${uid}`).set({blocked:true,suspendedUntil:Timestamp.fromMillis(untilMillis)},{merge:true});
  await audit(req.auth.uid,"USER_SUSPENDED",uid,{untilMillis});
  return {ok:true};
});
exports.submitSupportTicket = onCall(async req => {
  if (!req.auth) throw new HttpsError("unauthenticated","Sign in required.");
  const subject=String(req.data?.subject||"").trim().slice(0,120);
  const message=String(req.data?.message||"").trim().slice(0,3000);
  if (!subject || !message) throw new HttpsError("invalid-argument","Subject and message are required.");
  const ref=await db.collection("supportTickets").add({
    uid:req.auth.uid,subject,message,status:"open",createdAt:FieldValue.serverTimestamp()
  });
  return {ticketId:ref.id};
});
