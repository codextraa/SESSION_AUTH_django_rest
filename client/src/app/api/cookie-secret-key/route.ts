// src/app/api/cookie-secret-key/route.js
export async function GET(): Promise<Response> {
  const cookie_secret_key = process.env.NEXT_PUBLIC_COOKIE_SECRET_KEY;
  return new Response(JSON.stringify({ cookie_secret_key }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
