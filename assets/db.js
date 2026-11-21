/* ============================================================
 * Arc 共享数据层 db.js
 * 功能：账号注册 / 登录、档案（金币 / 战机 / 卡片 / 最高分）、成绩与排行榜
 * 数据库：Nhost Hasura GraphQL（免费云 Postgres）；未配置或网络不可达时
 *         自动降级到浏览器本地存储，保证离线可完整演示。
 * 对外接口（游戏与页面只依赖这些，签名保持稳定）：
 *   validate(username, password) -> 错误信息字符串 | null
 *   register(username, password) -> {username, nickname}
 *   login(username, password)    -> {username, nickname}
 *   logout()
 *   getSession() -> {username, nickname, loginAt} | null
 *   getProfile() -> 档案对象（游客返回默认档案，不入库）
 *   saveProfile(patch) -> 合并后的档案（游客返回默认档案）
 *   saveScore(game, score) -> {saved, best}
 *   getBest(game) -> number
 *   getLeaderboard(game, limit) -> [{username, score}]
 * ============================================================ */

const ARC_DB = (function () {
  // —— 申请/接入免费 Nhost 项目后，在控制台复制填入 ——
  const CONFIG = {
    url: "",        // 例：https://<hash>.graphql.eu-central-1.nhost.run/v1
    anonKey: ""     // 公开 anon JWT（role: anon），可公开下发前端
  };

  const LS_SESSION = "arc_session";
  const LS_LOCAL = "arc_local_db";
  const GUEST = "___guest___";

  const DEFAULT_PROFILE = {
    coins: 0,
    currentPlane: "starter",
    ownedPlanes: ["starter"],
    cards: { wpn: 0, shield: 0, wing: 0, engine: 0 },
    best: { plane: 0, block: 0 }
  };

  const READY = !!(CONFIG.url);

  /* ================= 本地兜底存储 ================= */
  function localLoad() {
    try {
      const d = JSON.parse(localStorage.getItem(LS_LOCAL));
      if (d && d.users && d.scores && d.profiles) return d;
    } catch (e) {}
    return { users: {}, scores: { plane: [], block: [] }, profiles: {} };
  }
  function localSave(d) { localStorage.setItem(LS_LOCAL, JSON.stringify(d)); }

  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function defaultProfile() { return clone(DEFAULT_PROFILE); }
  function mergeProfile(base, patch) {
    const p = Object.assign(defaultProfile(), base || {});
    p.cards = Object.assign(defaultProfile().cards, (base && base.cards) || {}, (patch && patch.cards) || {});
    p.best = Object.assign(defaultProfile().best, (base && base.best) || {}, (patch && patch.best) || {});
    if (patch) {
      if (typeof patch.coins === "number") p.coins = patch.coins;
      if (typeof patch.currentPlane === "string") p.currentPlane = patch.currentPlane;
      if (Array.isArray(patch.ownedPlanes)) p.ownedPlanes = patch.ownedPlanes.slice();
    }
    return p;
  }

  /* ================= 密码哈希（PBKDF2 / SHA-256） ================= */
  function bufToB64(buf) {
    const bytes = new Uint8Array(buf); let bin = "";
    bytes.forEach(b => (bin += String.fromCharCode(b)));
    return btoa(bin);
  }
  function b64ToBuf(b64) {
    const bin = atob(b64); const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }
  function randomSalt() {
    const arr = new Uint8Array(16); crypto.getRandomValues(arr);
    return bufToB64(arr.buffer);
  }
  async function hashPassword(password, saltB64) {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: b64ToBuf(saltB64), iterations: 100000, hash: "SHA-256" },
      km, 256
    );
    return bufToB64(bits);
  }

  /* ================= 会话 ================= */
  function getSession() {
    try { return JSON.parse(localStorage.getItem(LS_SESSION)); }
    catch (e) { return null; }
  }
  function setSession(user) {
    localStorage.setItem(LS_SESSION, JSON.stringify({
      username: user.username,
      nickname: user.nickname || user.username,
      loginAt: Date.now()
    }));
  }
  function logout() { localStorage.removeItem(LS_SESSION); }

  /* ================= 校验 ================= */
  function validate(username, password) {
    if (!/^[A-Za-z0-9_一-龥]{3,20}$/.test((username || "").trim()))
      return "用户名需为 3-20 位字母、数字、下划线或中文";
    if (!password || password.length < 4) return "密码长度至少 4 位";
    return null;
  }

  /* ================= 云：Hasura GraphQL ================= */
  async function gql(query, variables) {
    if (!READY) throw new Error("DB_NOT_CONFIGURED");
    const headers = { "Content-Type": "application/json" };
    if (CONFIG.anonKey) headers["Authorization"] = "Bearer " + CONFIG.anonKey;
    const resp = await fetch(CONFIG.url, {
      method: "POST",
      headers,
      body: JSON.stringify({ query, variables })
    });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const json = await resp.json();
    if (json.errors && json.errors.length) throw new Error(json.errors[0].message);
    return json.data;
  }

  async function cloudRegister(username, salt, passHash, nickname) {
    await gql(
      `mutation($u:String!,$s:String!,$h:String!,$n:String!){
        insert_accounts_one(object:{username:$u,salt:$s,pass_hash:$h,nickname:$n}){username}
      }`,
      { u: username, s: salt, h: passHash, n: nickname }
    );
    await cloudUpsertProfile(username, defaultProfile());
  }
  async function cloudGetUser(username) {
    const d = await gql(
      `query($u:String!){ accounts(where:{username:{_eq:$u}}){username,nickname,salt,pass_hash} }`,
      { u: username }
    );
    return d.accounts && d.accounts[0] || null;
  }
  async function cloudGetProfile(username) {
    const d = await gql(
      `query($u:String!){ profiles(where:{username:{_eq:$u}}){
        username coins current_plane owned_planes card_wpn card_shield card_wing card_engine best_plane best_block
      } }`,
      { u: username }
    );
    const r = d.profiles && d.profiles[0];
    if (!r) return defaultProfile();
    return {
      coins: r.coins || 0,
      currentPlane: r.current_plane || "starter",
      ownedPlanes: Array.isArray(r.owned_planes) ? r.owned_planes : ["starter"],
      cards: { wpn: r.card_wpn || 0, shield: r.card_shield || 0, wing: r.card_wing || 0, engine: r.card_engine || 0 },
      best: { plane: r.best_plane || 0, block: r.best_block || 0 }
    };
  }
  async function cloudUpsertProfile(username, profile) {
    const obj = Object.assign({ username }, profileToRow(profile));
    await gql(
      `mutation($obj:profiles_insert_input!){
        insert_profiles_one(object:$obj, on_conflict:{constraint:"profiles_pkey",update_columns:["coins","current_plane","owned_planes","card_wpn","card_shield","card_wing","card_engine","best_plane","best_block"]}){username}
      }`,
      { obj }
    );
  }
  function profileToRow(p) {
    return {
      coins: p.coins || 0,
      current_plane: p.currentPlane || "starter",
      owned_planes: p.ownedPlanes || ["starter"],
      card_wpn: p.cards.wpn || 0,
      card_shield: p.cards.shield || 0,
      card_wing: p.cards.wing || 0,
      card_engine: p.cards.engine || 0,
      best_plane: p.best.plane || 0,
      best_block: p.best.block || 0
    };
  }
  async function cloudAddScore(username, game, score) {
    await gql(
      `mutation($u:String!,$g:String!,$s:Int!){
        insert_scores_one(object:{username:$u,game:$g,score:$s}){id}
      }`,
      { u: username, g: game, s: score }
    );
  }
  async function cloudLeaderboard(game, limit) {
    const d = await gql(
      `query($g:String!){ scores(where:{game:{_eq:$g}},order_by:{score:desc}){username,score} }`,
      { g: game }
    );
    const best = {};
    (d.scores || []).forEach(r => { if (!best[r.username] || r.score > best[r.username]) best[r.username] = r.score; });
    return Object.keys(best).map(u => ({ username: u, score: best[u] }))
      .sort((a, b) => b.score - a.score).slice(0, limit);
  }

  /* ================= 本地：账号 / 档案 / 成绩 ================= */
  function localRegister(username, salt, passHash, nickname) {
    const db = localLoad();
    if (db.users[username]) throw new Error("该用户名已被注册");
    db.users[username] = { salt, pass_hash: passHash, nickname };
    db.profiles[username] = defaultProfile();
    localSave(db);
  }
  function localGetUser(username) {
    const db = localLoad();
    return db.users[username] ? Object.assign({ username }, db.users[username]) : null;
  }
  function localGetProfile(username) {
    const db = localLoad();
    return mergeProfile(db.profiles[username] || {}, {});
  }
  function localUpsertProfile(username, profile) {
    const db = localLoad();
    db.profiles[username] = mergeProfile(db.profiles[username] || {}, profile);
    localSave(db);
  }
  function localAddScore(username, game, score) {
    const db = localLoad();
    db.scores[game] = db.scores[game] || [];
    db.scores[game].push({ username, score, created_at: Date.now() });
    const u = db.profiles[username];
    if (u) {
      const key = game === "block" ? "best_block" : "best_plane";
      // 本地档案 best 结构
      u.best = u.best || { plane: 0, block: 0 };
      if (game === "block") u.best.block = Math.max(u.best.block || 0, score);
      else u.best.plane = Math.max(u.best.plane || 0, score);
    }
    localSave(db);
  }
  function localLeaderboard(game, limit) {
    const db = localLoad();
    const best = {};
    (db.scores[game] || []).forEach(r => { if (!best[r.username] || r.score > best[r.username]) best[r.username] = r.score; });
    return Object.keys(best)
      .map(u => ({ username: u, score: best[u] }))
      .sort((a, b) => b.score - a.score).slice(0, limit);
  }

  /* ================= 对外：注册 / 登录 ================= */
  async function register(username, password) {
    username = (username || "").trim();
    const v = validate(username, password);
    if (v) throw new Error(v);
    const salt = randomSalt();
    const passHash = await hashPassword(password, salt);
    if (READY) {
      try { await cloudRegister(username, salt, passHash, username); }
      catch (e) {
        if (String(e.message).includes("duplicate") || String(e.message).includes("已被"))
          throw new Error("该用户名已被注册");
        // 云不可达 → 降级本地
        localRegister(username, salt, passHash, username);
      }
    } else {
      localRegister(username, salt, passHash, username);
    }
    setSession({ username, nickname: username });
    return { username, nickname: username };
  }

  async function login(username, password) {
    username = (username || "").trim();
    if (!username || !password) throw new Error("请输入用户名和密码");

    let record = null;
    if (READY) {
      try { record = await cloudGetUser(username); }
      catch (e) { record = localGetUser(username); }
    } else {
      record = localGetUser(username);
    }
    if (!record) throw new Error("用户不存在，请先注册");
    const candidate = await hashPassword(password, record.salt);
    if (candidate !== record.pass_hash) throw new Error("密码错误");

    setSession(record);
    return { username: record.username, nickname: record.nickname || record.username };
  }

  /* ================= 对外：档案 ================= */
  async function getProfile() {
    const s = getSession();
    if (!s) return defaultProfile();
    if (READY) {
      try { return await cloudGetProfile(s.username); }
      catch (e) { return localGetProfile(s.username); }
    }
    return localGetProfile(s.username);
  }

  async function saveProfile(patch) {
    const s = getSession();
    if (!s) return defaultProfile();
    const cur = await getProfile();
    const next = mergeProfile(cur, patch);
    if (READY) {
      try { await cloudUpsertProfile(s.username, next); return next; }
      catch (e) { localUpsertProfile(s.username, next); return next; }
    }
    localUpsertProfile(s.username, next);
    return next;
  }

  /* ================= 对外：成绩 / 排行榜 ================= */
  async function saveScore(game, score) {
    const s = getSession();
    score = Math.max(0, Math.floor(Number(score) || 0));
    if (!s) return { saved: false, reason: "guest", best: 0 };

    let best = 0;
    if (READY) {
      try {
        await cloudAddScore(s.username, game, score);
        const prof = await cloudGetProfile(s.username);
        const curBest = game === "block" ? prof.best.block : prof.best.plane;
        if (score > curBest) {
          const patch = { best: {} };
          patch.best[game] = score;
          await cloudUpsertProfile(s.username, mergeProfile(prof, patch));
          best = score;
        } else best = curBest;
        return { saved: true, best };
      } catch (e) { /* 降级本地 */ }
    }
    localAddScore(s.username, game, score);
    const prof = localGetProfile(s.username);
    best = game === "block" ? prof.best.block : prof.best.plane;
    return { saved: true, best };
  }

  async function getBest(game) {
    const s = getSession();
    if (!s) return 0;
    const prof = await getProfile();
    return game === "block" ? (prof.best.block || 0) : (prof.best.plane || 0);
  }

  async function getLeaderboard(game, limit) {
    limit = limit || 10;
    if (READY) {
      try { return await cloudLeaderboard(game, limit); }
      catch (e) { return localLeaderboard(game, limit); }
    }
    return localLeaderboard(game, limit);
  }

  return {
    READY, CONFIG,
    validate, register, login, logout, getSession,
    getProfile, saveProfile,
    saveScore, getBest, getLeaderboard
  };
})();
