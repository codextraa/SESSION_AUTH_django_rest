// src/app/api/auth-secret-key/route.js
export async function GET() {
  const auth_secret_key = process.env.NEXT_PUBLIC_AUTH_SECRET_KEY;
  return new Response(JSON.stringify({ auth_secret_key }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
