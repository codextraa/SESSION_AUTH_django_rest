// src/app/api/recaptcha-key/route.js
export async function GET() {
  const sitekey = process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY;
  return new Response(JSON.stringify({ sitekey }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
