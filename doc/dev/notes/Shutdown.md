# Safe shutdown in arti

General proposal (inspired by tokio's CancellationToken capabilities,
and much simplified):

We create a new channel type, with a "ShutdownSender" and a
"ShutdownReceiver".

"ShutdownReceiver" is a future.
When Arti is trying to shut down, this future becomes ready.
We give a copy of this future to every task we spawn.
When the future becomes ready, the task should clean up, exit,
and drop the future.

For tasks or futures that don't need to do anything besides "Stop",
we provide a Cancellable<> wrapper around Future that takes
a ShutdownReceiver.

For stream-driven tasks,
we may provide a wrapper that makes a stream "done" once we are shutting down.

There is also a ShutdownCompletion future.  When the last
ShutdownReceiver for a ShutdownSender is dropped, then ShutdownCompletion
becomes ready.

TorClient get an `async fn shutdown(&self)` that tells the ShutdownSender
to stop, waits for a ShutdownCompletion, and transitions the TorClient
to a dormant state, as if it had been created un-bootstrapped.
Once this function is called, and until it returns,
other functions on the TorClient that would use the network all
return a "Shutting Down" error.


## Open questions

Do we want to provide a 'slow shutdown' signal,
to give things a little time to finish before we kill them completely?
If so, what does that look like?  Does that use a different mechanism?

Presuming that we use this mechanism with `arti` proxies via RPC,
what's the API to get those things a ShutdownReceiver?

Do we really need to audit every place that we spawn something?
How do we know that we actually shut everything down correctly?

Does this interact with dormant status?  If so, how?


