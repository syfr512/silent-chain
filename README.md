# silent-chain
A Burp Suite extension for authorized web security labs. It streams lightweight HTTP telemetry to OpenAI through a non-blocking Jython worker thread and returns concise defensive attack-path analysis in the Burp extension console.

Tested on Burp Suite Community Edition v2026.4.3 using standalone Jython 2.7.4, running on the gpt4o-mini model.
