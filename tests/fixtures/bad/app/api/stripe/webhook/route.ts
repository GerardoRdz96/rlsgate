// no signature verification -> unverified-webhook (HIGH)
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') {
    await grantAccess(event.data.object.customer);
  }
  return new Response('ok');
}
