using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using Leaf.xNet.Services.Captcha;

namespace Leaf.xNet.Services.Cloudflare
{
    /// <summary>
    /// CloudFlare Anti-DDoS bypass extension for HttpRequest.
    /// </summary>
    /// <remarks>
    /// Only the JavaScript challenge can be handled. CAPTCHA and IP address blocking cannot be bypassed.
    /// </remarks>
    // ReSharper disable once UnusedMember.Global
    public static class CloudflareBypass
    {
        #region Public / Private: Data

        /// <summary>
        /// Delegate for Log message to UI.
        /// </summary>
        /// <param name="message">Message</param>
        public delegate void DLog(string message);

        /// <summary>
        /// Cookie key name used for identify CF clearance.
        /// </summary>
        public const string CfClearanceCookie = "cf_clearance";

        /// <summary>
        /// Default Accept-Language header added to Cloudflare server request.
        /// </summary>
        public static string DefaultAcceptLanguage { get; set; } = "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7";

        /// <summary>
        /// Gets or sets the number of clearance retries, if clearance fails.
        /// </summary>
        /// <remarks>A negative value causes an infinite amount of retries.</remarks>
        public static int MaxRetries { get; set; } = 4;

        /// <summary>
        /// Delay before post form with solution in milliseconds.
        /// </summary>
        /// <remarks>Recommended value is 4000 ms. You can look extract value at challenge HTML. Second argument of setTimeout().</remarks>
        public static int DelayMilliseconds { get; set; } = 5000;

        private const string LogPrefix = "[Cloudflare] ";

        #endregion


        #region Public: Http Extensions

        /// <summary>
        /// Check response for Cloudflare protection.
        /// </summary>
        /// <returns>Returns <keyword>true</keyword> if response has Cloudflare protection challenge.</returns>
        public static bool IsCloudflared(this HttpResponse response)
        {
            bool serviceUnavailable = response.StatusCode == HttpStatusCode.ServiceUnavailable || response.StatusCode == HttpStatusCode.Forbidden;
            bool cloudflareServer = response[HttpHeader.Server].IndexOf("cloudflare", StringComparison.OrdinalIgnoreCase) != -1;

            return serviceUnavailable && cloudflareServer;
        }

        /// <summary>
        /// GET request with bypassing Cloudflare JavaScript challenge.
        /// </summary>
        /// <param name="request">Http request</param>
        /// <param name="uri">Uri Address</param>
        /// <param name="log">Log action</param>
        /// <param name="cancellationToken">Cancel protection</param>
        /// <param name="captchaSolver">Captcha solving provider when Recaptcha required for pass</param>
        /// <exception cref="HttpException">When HTTP request failed</exception>
        /// <exception cref="CloudflareException">When unable to bypass Cloudflare</exception>
        /// <exception cref="CaptchaException">When unable to solve captcha using <see cref="ICaptchaSolver"/> provider.</exception>
        /// <returns>Returns original HttpResponse</returns>
        private static HttpResponse GetThroughCloudflare(this HttpRequest request,HttpMethod httpMethod, Uri uri , string postData = null, string contentType = null,
            DLog log = null,
            CancellationToken cancellationToken = default(CancellationToken),
            ICaptchaSolver captchaSolver = null)
        {
            if (!request.UseCookies)
                throw new CloudflareException($"{LogPrefix}Cookies must be enabled. Please set ${nameof(HttpRequest.UseCookies)} to true.");

            // User-Agent is required
            if (string.IsNullOrEmpty(request.UserAgent))
                request.UserAgent = Http.ChromeUserAgent();

            log?.Invoke($"{LogPrefix}Checking availability at: {uri.AbsoluteUri} ...");

            for (int i = 0; i < MaxRetries; i++)
            {
                string retry = $". Retry {i + 1} / {MaxRetries}.";
                log?.Invoke($"{LogPrefix}Trying to bypass{retry}");

                HttpResponse response;
                switch(httpMethod)
                {
                    case HttpMethod.POST:
                        response = ManualPost(request, uri, postData, contentType);
                        break;
                    case HttpMethod.GET:
                        response = ManualGet(request, uri);
                        break;
                    default:
                        response = ManualGet(request, uri);
                        break;
                }
                    
                
                    

                if (!response.IsCloudflared())
                {
                    log?.Invoke($"{LogPrefix} OK. Not found at: {uri.AbsoluteUri}");
                    return response;
                }

                // Remove expired clearance if present
                var cookies = request.Cookies.GetCookies(uri);
                foreach (Cookie cookie in cookies)
                {
                    if (cookie.Name != CfClearanceCookie) 
                        continue;

                    cookie.Expired = true;
                    break;
                }

                if (cancellationToken != default(CancellationToken))
                    cancellationToken.ThrowIfCancellationRequested();

                // Bypass depend on challenge type: JS / Recaptcha
                //
                if (HasJsChallenge(response))
                    SolveJsChallenge(ref response, request, uri, retry, log, cancellationToken);
                
                if (HasRecaptchaChallenge(response))
                    SolveRecaptchaChallenge(ref response, request, uri, retry, log, cancellationToken);

                if (response.IsCloudflared())
                {
                    throw new CloudflareException(HasAccessDeniedError(response)
                        ? "Access denied. Try to use another IP address."
                        : "Unknown challenge type");
                }

                return response;
            }

            throw new CloudflareException(MaxRetries, $"{LogPrefix}ERROR. Rate limit reached.");
        }

        /// <summary>
        /// GET,POST request with bypassing Cloudflare JavaScript challenge.
        /// </summary>
        /// <param name="request"></param>
        /// <param name="url">URL address</param>
        /// <param name="httpMethod">Available now: Get(default),Post</param>
        /// <param name="Data">RequestContent in raw</param>
        /// <param name="contentType">Content-Type</param>
        /// <param name="log">Log action</param>
        /// <param name="cancellationToken">Cancel protection</param>
        /// <param name="captchaSolver">Captcha solving provider when Recaptcha required for pass</param>
        /// <returns></returns>
        public static HttpResponse GetThroughCloudflare(this HttpRequest request, string url, HttpMethod httpMethod = HttpMethod.GET, string Data = null, string contentType = "application/x-www-form-urlencoded",
            DLog log = null,
            CancellationToken cancellationToken = default(CancellationToken),
            ICaptchaSolver captchaSolver = null)
        {
            var uri = request.BaseAddress != null && url.StartsWith("/") ? new Uri(request.BaseAddress, url) : new Uri(url);
            return GetThroughCloudflare(request, httpMethod, uri, Data, contentType, log, cancellationToken, captchaSolver);
        }
        #endregion

        #region Private: Generic Challenge
        
        private static bool IsChallengePassed(string tag, ref HttpResponse response, HttpRequest request, Uri uri, string retry, DLog log)
        {

            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (response.StatusCode) {
                case HttpStatusCode.ServiceUnavailable:
                case HttpStatusCode.Forbidden:
                    return false;
                case HttpStatusCode.Found:
                    // Т.к. ранее использовался ручной режим - нужно обработать редирект, если он есть, чтобы вернуть отфильтрованное тело запроса    
                    if (response.HasRedirect)
                    {
                        if (!response.ContainsCookie(uri, CfClearanceCookie))
                            return false;

                        log?.Invoke($"{LogPrefix}Passed [{tag}]. Trying to get the original response at: {uri.AbsoluteUri} ...");

                        // Не используем manual т.к. могут быть переадресации
                        bool ignoreProtocolErrors = request.IgnoreProtocolErrors;
                        // Отключаем обработку HTTP ошибок
                        request.IgnoreProtocolErrors = true;

                        request.AddCloudflareHeaders(uri); // заголовки важны для прохождения cloudflare
                        response = request.Get(response.RedirectAddress.AbsoluteUri);
                        request.IgnoreProtocolErrors = ignoreProtocolErrors;

                        if (IsCloudflared(response))
                        {
                            log?.Invoke($"{LogPrefix}ERROR [{tag}]. Unable to get he original response at: {uri.AbsoluteUri}");
                            return false;
                        }
                    }

                    log?.Invoke($"{LogPrefix}OK [{tag}]. Done: {uri.AbsoluteUri}");
                    return true;
            }

            log?.Invoke($"{LogPrefix}ERROR [{tag}]. Status code : {response.StatusCode}{retry}.");
            return false;
        }

        #endregion


        #region Private: Challenge (JS)

        private static bool HasJsChallenge(HttpResponse response) => response.ToString().ContainsInsensitive("jschl-answer");

        private static bool SolveJsChallenge(ref HttpResponse response, HttpRequest request, Uri uri, string retry, 
            DLog log, CancellationToken cancellationToken)
        {
            log?.Invoke($"{LogPrefix}Solving JS Challenge for URL: {uri.AbsoluteUri} ...");
            response = PassClearance(request, response, uri, log, cancellationToken);

            return IsChallengePassed("JS", ref response, request, uri, retry, log);
        }

        private static Uri GetSolutionUri(HttpResponse response)
        {
            string pageContent = response.ToString();
            string scheme = response.Address.Scheme;
            string host = response.Address.Host;
            int port = response.Address.Port;
            var solution = ChallengeSolver.Solve(pageContent, host, port);

            return new Uri($"{scheme}://{host}:{port}{solution.ClearanceQuery}");
        }

        private static HttpResponse PassClearance(HttpRequest request, HttpResponse response, Uri refererUri,
            DLog log, CancellationToken cancellationToken)
        {
            // Using Uri for correct port resolving
            var uri = GetSolutionUri(response);

            Delay(DelayMilliseconds, log, cancellationToken);

            return request.ManualGet(uri, refererUri);
        }

        #endregion


        #region Private: Challenge (Recaptcha)

        private static bool HasRecaptchaChallenge(HttpResponse response)
        {
            // Cross-platform string.Contains
            return response.ToString().IndexOf("<div class=\"g-recaptcha\">", StringComparison.OrdinalIgnoreCase) != -1;
        }

        private static bool SolveRecaptchaChallenge(ref HttpResponse response, HttpRequest request, Uri uri, string retry, 
            DLog log, CancellationToken cancelToken)
        {
            log?.Invoke($"{LogPrefix}Solving Recaptcha Challenge for URL: {uri.AbsoluteUri} ...");

            if (request.CaptchaSolver == null)
                throw new CloudflareException($"{nameof(HttpRequest.CaptchaSolver)} required");

            string respStr = response.ToString();
            string siteKey = respStr.Substring("data-sitekey=\"", "\"")
                ?? throw new CloudflareException("Value of \"data-sitekey\" not found");

            string s = respStr.Substring("name=\"s\" value=\"", "\"")
                ?? throw new CloudflareException("Value of \"s\" not found");

            string rayId = respStr.Substring("data-ray=\"", "\"")
                ?? throw new CloudflareException("Ray Id not found");

            string answer = request.CaptchaSolver.SolveRecaptcha(uri.AbsoluteUri, siteKey, cancelToken);
            
            cancelToken.ThrowIfCancellationRequested();

            var rp = new RequestParams {
                    ["s"] = s,
                    ["id"] = rayId,
                    ["g-recaptcha-response"] = answer
            };

            string bfChallengeId = respStr.Substring("'bf_challenge_id', '", "'");
            if (bfChallengeId != null)
            {
                rp.Add(new KeyValuePair<string, string>("bf_challenge_id", bfChallengeId));
                rp.Add(new KeyValuePair<string, string>("bf_execution_time", "4"));
                rp.Add(new KeyValuePair<string, string>("bf_result_hash", string.Empty));
            }

            response = request.ManualGet(new Uri(uri, "/cdn-cgi/l/chk_captcha"), uri, rp);

            return IsChallengePassed("ReCaptcha", ref response, request, uri, retry, log);
        }

        #endregion


        #region Private: Error Handling

        private static bool HasAccessDeniedError(HttpResponse response)
        {
            string resp = response.ToString();
            string title = resp.Substring("class=\"cf-subheadline\">", "<")
                ?? resp.Substring("<title>", "</title>");

            return !string.IsNullOrEmpty(title) && title.ContainsInsensitive("Access denied");
        }

        #endregion

        #region Private: HttpRequest Extensions & Tools

        private static HttpResponse ManualGet(this HttpRequest request, Uri uri, Uri refererUri = null, RequestParams requestParams = null)
        {
            request.ManualMode = true;
            // Manual start

            request.AddCloudflareHeaders(refererUri ?? uri);
            var response = requestParams == null ? request.Get(uri) : request.Get(uri, requestParams);

            // End manual mode
            request.ManualMode = false;

            return response;
        }
        private static HttpResponse ManualPost(this HttpRequest request, Uri uri,string postData,string contentType ,Uri refererUri = null, RequestParams requestParams = null)
        {
            request.ManualMode = true;
            // Manual start

            request.AddCloudflareHeaders(refererUri ?? uri);
            HttpResponse response;
            if(string.IsNullOrEmpty(postData) & contentType != "application/x-www-form-urlencoded")
            {
                var stringContent = new StringContent(string.Empty) { ContentType = contentType };
                response = request.Raw(HttpMethod.POST, uri, stringContent);
            }
            else if(!string.IsNullOrEmpty(postData))
            {
                response = request.Post(uri, postData, contentType);
            }
            else
            {
                response = request.Post(uri);
            }

            // End manual mode
            request.ManualMode = false;

            return response;
        }
        private static void AddCloudflareHeaders(this HttpRequest request, Uri refererUri)
        {
            request.AddHeader(HttpHeader.Referer, refererUri.AbsoluteUri);
            request.AddHeader(HttpHeader.Accept, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8");
            request.AddHeader("Upgrade-Insecure-Requests", "1");
            
            if (!request.ContainsHeader(HttpHeader.AcceptLanguage))
                request.AddHeader(HttpHeader.AcceptLanguage, DefaultAcceptLanguage);
        }

        private static void Delay(int milliseconds, DLog log, CancellationToken cancellationToken)
        {
            log?.Invoke($"{LogPrefix}: delay {milliseconds} ms...");

            if (cancellationToken == default(CancellationToken))
                Thread.Sleep(milliseconds);
            else
            {
                cancellationToken.WaitHandle.WaitOne(milliseconds);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        #endregion
    }
}
