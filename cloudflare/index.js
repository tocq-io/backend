addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event.request))
})
/**
 * One simple switch to handle the routing of data storage
 * @param {Request} request
 */
async function handleRequest(request) {
  //const host = request.headers.get('host')
  const url = new URL(request.url)
  const path = url.pathname.toLowerCase().split('/')
  const receiver = path[1]

  switch (request.method.toLowerCase()) {
    case 'get':
      // could be a string instead of a stream, not clear what is really better
      const data = await tocq_data.get(receiver, { type: 'stream' })
      if (data) {
        return new Response(data, {
          headers: { 'content-type': 'text/plain' },
        })
      } else {
        return new Response((status = 404))
      }
    case 'put':
      const sender = path.length > 2 ? path[2] : null
      //TODO this is not very elegant as it waits for the stream to be read
      const req_data = await request.text()
      let rec_promise = tocq_data.put(receiver, req_data, {
        expirationTtl: 3600,
      })
      if (sender) {
        let snd_promise = tocq_data.put(sender, req_data, {
          expirationTtl: 3600,
        })
        await Promise.all([rec_promise, snd_promise])
      } else {
        await rec_promise
      }
      return new Response((status = 201))
    case 'delete':
      // maybe only delete own messages
      await tocq_data.delete(receiver)
      return new Response((status = 200))
    case 'post':
    //TODO This will be publishing logic
    default:
      return new Response((status = 501))
  }
}
