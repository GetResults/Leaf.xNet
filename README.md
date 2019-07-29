# Fork Features
In this fork have support to use CloudFlare bypass with POST requests.

### CloudFlare bypass with POST requests
For Get request:

```csharp
using Leaf.xNet.Services.Cloudflare;

var httpRequest = new HttpRequest();
var clearResp = httpRequest.GetThroughCloudflare("https://...");

```

For POST request:
```csharp
string postData = $"UserId={Login}&SessionInfo={token}&Password={Password}&.........";
var response = httpRequest.GetThroughCloudflare("https://...", HttpMethod.POST, postData);
```

If need bypass CloudFlare with POST request without "postData", in the parameters need send null or empty string.
