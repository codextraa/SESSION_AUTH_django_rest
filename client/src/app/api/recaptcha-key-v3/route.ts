// src/app/api/recaptcha-key-v3/route.ts
export async function GET(): Promise<Response> {
  const sitekey = process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY_V3;
  return new Response(JSON.stringify({ sitekey }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
