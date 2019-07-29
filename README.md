# Fork Features
In this fork have support to use CloudFlare bypass with POST requests.

### CloudFlare bypass with POST requests
See demo project in the Examples folder.

```csharp
using Leaf.xNet.Services.Cloudflare;

// Check and pass CloudFlare JS Challange if it's present
// Attention: It's working when Re-Captcha enabled
var httpRequest = new HttpRequest();
var clearResp = httpRequest.GetThroughCloudflare("https://...");

// Check only (without solution)
var resp = httpRequest.Get("https://...");
bool isCloudFlared = resp.isCloudFlared();
```
