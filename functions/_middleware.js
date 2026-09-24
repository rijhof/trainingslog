const enc = new TextEncoder();
const hash = s => crypto.subtle.digest("SHA-256", enc.encode(s));

export async function onRequest({ request, env, next }) {
  const [scheme, value] = (request.headers.get("Authorization") || "").split(" ");
  // env.CREDENTIALS = "user:passwort"; SHA-256 first so timingSafeEqual gets equal-length buffers
  if (scheme === "Basic" && value && env.CREDENTIALS) {
    if (crypto.subtle.timingSafeEqual(await hash(atob(value)), await hash(env.CREDENTIALS))) return next();
  }
  return new Response("Passwort erforderlich", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="Trainingslog", charset="UTF-8"' },
  });
}
