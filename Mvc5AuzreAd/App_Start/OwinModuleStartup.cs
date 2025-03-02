using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Mvc5AuzreAd;
using Owin;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Text.Encodings.Web;

[assembly: OwinStartup(typeof(OwinModuleStartup))] // This is the registration of startup class for Owin

namespace Mvc5AuzreAd
{
    public class OwinModuleStartup
    {
        public const string IdentityProviderCookieKey = "ipd";
        public const string IdentityProviderLoginHintCookieKey = "idp.login_hint";
        public const string IdentityProviderCookieValueB2C = "b2c";
        public const string IdentityProviderCookieValueAAD = "aad";
        private const string DefaultAuthenticationType = "ApplicationCookie";
        public void Configuration(IAppBuilder app)
        {

            // Get OpenIdConnectConfiguration for Bearer token validation.
            var authority = ConfigurationManager.AppSettings["OpenIdAzureAdJwtAuthority"];

            var wellKnownEndpoint = $"{authority}/.well-known/openid-configuration";
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                wellKnownEndpoint, new OpenIdConnectConfigurationRetriever());

            var openIdConfig = Task.Run(() => configurationManager.GetConfigurationAsync()).Result;

            // Configure OAuth Bearer token authentication
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                Provider = new OAuthBearerAuthenticationProvider
                {
                    OnRequestToken = async context =>
                    {
                        // Ensure Bearer token is in the Authorization header
                        var token = context.Request.Headers.Get("Authorization")?.Replace("Bearer ", "");

                        if (string.IsNullOrEmpty(token))
                        {
                            await Task.CompletedTask;
                            return;
                        }

                        try
                        {
                            var tokenHandler = new JwtSecurityTokenHandler();

                            var validationParameters = new TokenValidationParameters
                            {
                                ValidateIssuer = true,
                                ValidIssuer = ConfigurationManager.AppSettings["OpenIdAzureAdJwtIssuer"],
                                ValidateAudience = true,
                                ValidAudience = ConfigurationManager.AppSettings["OpenIdAzureAdJwtValidAudience"],
                                ValidateIssuerSigningKey = true,
                                IssuerSigningKeys = openIdConfig.SigningKeys,
                                ValidateLifetime = true
                            };

                            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

                            var claimsIdentity = (ClaimsIdentity)principal.Identity;

                            if (!claimsIdentity.HasClaim(c => c.Type == "IsExternal")) // Add extral claim if needed
                            {
                                claimsIdentity.AddClaim(new Claim("IsExternal", "False", "Boolean"));
                            }

                            var cp = new ClaimsIdentity(claimsIdentity.Claims, "JWT", ClaimTypes.Name, ClaimTypes.Role);

                            context.OwinContext.Authentication.User = new ClaimsPrincipal(cp);
                        }
                        catch (SecurityTokenExpiredException)
                        {
                            // Handle expired token - return 401 without redirecting
                            context.Response.StatusCode = 401;
                            context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"Token has expired\"");
                        }
                        catch (SecurityTokenValidationException)
                        {
                            // Handle invalid token - return 401 without redirecting
                            context.Response.StatusCode = 401;
                            context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"Token validation failed\"");
                        }
                        catch (Exception)
                        {
                            // Handle unexpected validation errors
                            context.Response.StatusCode = 500;
                            context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"server_error\", error_description=\"Token validation error\"");
                        }

                        await Task.CompletedTask;
                    }
                }
            });

            app.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                CookieSameSite = SameSiteMode.None,
                CookieDomain = ConfigurationManager.AppSettings["OpenIdCookieDomain"],
                AuthenticationType = DefaultAuthenticationType,
                LoginPath = new PathString(ConfigurationManager.AppSettings["OpenIdLoginRedirect"]),
                LogoutPath = new PathString(ConfigurationManager.AppSettings["OpenIdLogoutRedirect"]),
                Provider = new CookieAuthenticationProvider
                {
                    OnApplyRedirect = context =>
                    {
                        var token = context.Request.Headers.Get("Authorization")?.Replace("Bearer ", "");

                        if (!string.IsNullOrEmpty(token))
                        {
                            context.Response.StatusCode = 401;
                            context.Response.Headers.Remove("Location");
                            context.Response.Write("reauth_failed,bearer_provider");
                            return;
                        }

                        if (IsAjaxRequest(context.OwinContext) && context.OwinContext.Response.Headers.Any(i =>
                                i.Key == "X-ReauthState" && i.Value != null &&
                                i.Value.Contains("NoActiveProviderSession")))
                        {
                            context.Response.StatusCode = 401;
                            context.Response.Headers.Remove("Location");
                            context.Response.Write("reauth_failed,no_active_provider_session");
                        }
                        else if (IsAjaxRequest(context.OwinContext))
                        {
                            // For AJAX requests, return 401 Unauthorized without redirecting
                            context.Response.StatusCode = 401;
                            context.Response.Headers.Remove("Location");
                            context.Response.Write("reauth_required");
                        }
                        else
                        {
                            // For non-AJAX requests, perform the standard redirect to the login page
                            context.Response.Redirect(context.RedirectUri);
                        }
                    }
                }
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = ConfigurationManager.AppSettings["OpenIdAzureAdClientId"],
                ClientSecret = ConfigurationManager.AppSettings["OpenIdAzureAdClientSecret"],
                Authority = ConfigurationManager.AppSettings["OpenIdAzureAdAuthority"],
                RedirectUri = ConfigurationManager.AppSettings["OpenIdAzureAdRedirectUri"],
                PostLogoutRedirectUri = ConfigurationManager.AppSettings["OpenIdAzureAdPostLogoutRedirectUri"],
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                Scope = ConfigurationManager.AppSettings["OpenIdAzureAdClientScopes"],
                AuthenticationMode = AuthenticationMode.Passive,
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidAudiences = ConfigurationManager.AppSettings["OpenIdAzureAdValidAudiences"].Split(','),
                    ValidIssuers = ConfigurationManager.AppSettings["OpenIdAzureAdValidIssuers"].Split(','),
                    NameClaimType = ConfigurationManager.AppSettings["OpenIdAzureAdNameClaimType"],
                    RoleClaimType = ConfigurationManager.AppSettings["OpenIdAzureAdRoleClaimType"]
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = context =>
                    {
                        if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            // Prevent redirecting to Microsoft logout page
                            context.HandleResponse();

                            context.Response.Redirect("/account/postsignout");

                            return Task.CompletedTask;
                        }

                        // Add "domain_hint" to redirect users to correct login type (work/school vs personal)
                        context.ProtocolMessage.DomainHint = "organizations";  // or "consumers" for personal accounts

                        var cookie = context.Request.Cookies[IdentityProviderLoginHintCookieKey];
                        if (cookie != null)
                        {
                            context.ProtocolMessage.Prompt = "none";
                            context.ProtocolMessage.LoginHint = cookie;
                        }
                        else
                        {
                            if (IsAjaxRequest(context.OwinContext))
                            {
                                context.HandleResponse();
                                context.Response.Write("no_account_selected");
                                context.Response.StatusCode = 401;
                                return Task.CompletedTask;
                            }

                            context.ProtocolMessage.Prompt = "select_account";
                        }

                        return Task.CompletedTask;
                    },
                    AuthenticationFailed = context =>
                    {
                        if (context.Exception.Message.Contains("AADSTS50058") && IsAjaxRequest(context.OwinContext))
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = 401;
                            context.Response.Headers.Append("X-ReauthState", "NoActiveProviderSession");
                            RemoveLoginCookies(context.OwinContext);
                            return Task.FromResult(0);
                        }

                        if (context.Exception.Message.Contains("AADSTS50058"))
                        {
                            if (context.Request.Headers.ContainsKey("sec-fetch-dest") && context.Request.Headers["sec-fetch-dest"] == "iframe")
                            {
                                context.HandleResponse();
                                context.Response.StatusCode = 401;

                                RemoveLoginCookies(context.OwinContext);

                                context.Response.Redirect("/error/AuthenticationFailed");
                                return Task.CompletedTask;
                            }

                            context.HandleResponse();
                            RemoveLoginCookies(context.OwinContext);
                            context.Response.Redirect("/error/AuthenticationFailed");
                            return Task.FromResult(0);
                        }

                        if (context.Request != null && IsAjaxRequest(context.OwinContext))
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = 401;
                            context.Response.Write("reauth_required");
                            return Task.FromResult(0);
                        }

                        context.HandleResponse();

                        RemoveLoginCookies(context.OwinContext);

                        context.Response.Redirect("/account/login");
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = context =>
                    {
                        var identity = context.AuthenticationTicket.Identity;

                        if (!identity.HasClaim(c => c.Type == "IsExternal"))
                        {
                            identity.AddClaim(new Claim("IsExternal", "False", "Boolean"));
                        }

                        if (!identity.HasClaim(c => c.Type == IdentityProviderCookieKey))
                        {
                            identity.AddClaim(new Claim(IdentityProviderCookieKey, IdentityProviderCookieValueAAD, "string"));
                        }

                        var cookie = context.Request.Cookies[IdentityProviderCookieKey];

                        if (cookie == null)
                        {
                            context.Response.Cookies.Append(IdentityProviderCookieKey, IdentityProviderCookieValueAAD, new CookieOptions() { SameSite = SameSiteMode.Lax, HttpOnly = false, Secure = false }); // Add the cookie to the response
                        }

                        if (context.AuthenticationTicket.Identity.HasClaim(p => p.Type == ConfigurationManager.AppSettings["OpenIdAzureAdLoginHintCookieClaimType"]))
                        {
                            context.Response.Cookies.Append(IdentityProviderLoginHintCookieKey, context.AuthenticationTicket.Identity.Claims.First(i => i.Type == ConfigurationManager.AppSettings["OpenIdAzureAdLoginHintCookieClaimType"]).Value, new CookieOptions() { SameSite = SameSiteMode.Lax, HttpOnly = true, Secure = context.Request.IsSecure }); // Add the cookie to the response
                        }

                        return Task.FromResult(0);
                    }
                },
            });

            app.UseOpenIdConnectAuthentication(
              new OpenIdConnectAuthenticationOptions
              {
                  ClientId = ConfigurationManager.AppSettings["OpenIdAzureAdB2CClientId"],
                  ClientSecret = ConfigurationManager.AppSettings["OpenIdAzureAdB2CClientSecret"],
                  Authority = ConfigurationManager.AppSettings["OpenIdAzureAdB2CAuthority"],
                  RedirectUri = ConfigurationManager.AppSettings["OpenIdAzureAdB2CRedirectUri"],
                  PostLogoutRedirectUri = ConfigurationManager.AppSettings["OpenIdAzureAdB2CPostLogoutRedirectUri"],
                  ResponseType = OpenIdConnectResponseType.IdTokenToken,
                  Scope = ConfigurationManager.AppSettings["OpenIdAzureAdB2CClientScopes"],
                  AuthenticationMode = AuthenticationMode.Passive,
                  TokenValidationParameters = new TokenValidationParameters
                  {
                      ValidateAudience = true,
                      ValidateIssuer = true,
                      ValidAudiences = ConfigurationManager.AppSettings["OpenIdAzureAdB2CValidAudiences"].Split(','),
                      ValidIssuers = ConfigurationManager.AppSettings["OpenIdAzureAdB2CValidIssuers"].Split(','),
                      NameClaimType = ConfigurationManager.AppSettings["OpenIdAzureAdB2CNameClaimType"],
                  },
                  AuthenticationType = "AzureADB2C",
                  Notifications = new OpenIdConnectAuthenticationNotifications
                  {
                      AuthenticationFailed = context =>
                      {
                          if (context.Exception.Message.Contains("AADB2C90118"))
                          {
                              context.HandleResponse();
                              context.Response.Redirect("/Account/ResetPassword");
                              return Task.FromResult(0);
                          }

                          if ((context.Exception.Message.Contains("AADSTS50058") || context.Exception.Message.Contains("AADB2C90077")) && IsAjaxRequest(context.OwinContext))
                          {
                              context.HandleResponse();
                              context.Response.StatusCode = 401;
                              context.Response.Headers.Append("X-ReauthState", "NoActiveProviderSession");
                              RemoveLoginCookies(context.OwinContext);
                              return Task.FromResult(0);
                          }

                          if (context.Exception.Message.Contains("AADSTS50058") || context.Exception.Message.Contains("AADB2C90077"))
                          {
                              context.HandleResponse();
                              RemoveLoginCookies(context.OwinContext);
                              context.Response.Redirect("/error/AuthenticationFailed");
                              return Task.FromResult(0);
                          }

                          context.HandleResponse();

                          RemoveLoginCookies(context.OwinContext);

                          context.Response.Redirect("/account/login");
                          return Task.FromResult(0);
                      },
                      SecurityTokenValidated = context =>
                      {
                          var identity = context.AuthenticationTicket.Identity;

                          var requiredClaim = identity.FindFirst("extension_PortalAccountsPerm");

                          if (requiredClaim == null)
                          {
                              context.HandleResponse();
                              context.Response.StatusCode = 401;
                              context.Response.Write("Unauthorized: Required claim missing or invalid.");
                              return Task.FromResult(0);
                          }

                          if (!requiredClaim.Value.Split(',').Any(i => i.Equals("Pw2", StringComparison.InvariantCultureIgnoreCase)))
                          {
                              context.HandleResponse();
                              context.Response.StatusCode = 401;
                              context.Response.Write("Unauthorized: Required claim missing or invalid.");
                              return Task.FromResult(0);
                          }

                          if (!identity.HasClaim(c => c.Type == "IsExternal"))
                          {
                              identity.AddClaim(new Claim("IsExternal", "True", "Boolean"));
                          }

                          if (!identity.HasClaim(c => c.Type == IdentityProviderCookieKey))
                          {
                              identity.AddClaim(new Claim(IdentityProviderCookieKey, IdentityProviderCookieValueB2C, "string"));
                          }

                          var cookie = context.Request.Cookies[IdentityProviderCookieKey];

                          if (cookie == null)
                          {
                              context.Response.Cookies.Append(IdentityProviderCookieKey, IdentityProviderCookieValueB2C, new CookieOptions() { SameSite = SameSiteMode.Lax, HttpOnly = false, Secure = false }); // Add the cookie to the response// context.Response.Cookies.Append("ASP.NET_SessionId", "", new CookieOptions() { Expires = DateTime.UtcNow.AddYears(1), SameSite = SameSiteMode.Lax, HttpOnly = true, Secure = context.Request.IsSecure }); // Add the cookie to the response
                          }

                          if (context.AuthenticationTicket.Identity.HasClaim(p => p.Type == "emails"))
                          {
                              context.Response.Cookies.Append(IdentityProviderLoginHintCookieKey, context.AuthenticationTicket.Identity.Name, new CookieOptions() { SameSite = SameSiteMode.Lax, HttpOnly = true, Secure = context.Request.IsSecure }); // Add the cookie to the response
                          }

                          return Task.FromResult(0);
                      },
                      RedirectToIdentityProvider = context =>
                      {
                          if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                          {
                              // Prevent redirecting to Microsoft logout page
                              context.HandleResponse();

                              context.Response.Redirect("/account/postsignout");

                              return Task.CompletedTask;
                          }

                          var cookie = context.Request.Cookies[IdentityProviderLoginHintCookieKey];
                          if (cookie != null)
                          {
                              context.ProtocolMessage.Prompt = "none";
                              context.ProtocolMessage.LoginHint = cookie;
                          }
                          else
                          {
                              if (IsAjaxRequest(context.OwinContext))
                              {
                                  context.HandleResponse();
                                  context.Response.Write("no_account_selected");
                                  context.Response.StatusCode = 401;
                                  return Task.CompletedTask;
                              }

                              context.ProtocolMessage.Prompt = "select_account";
                          }

                          return Task.CompletedTask;
                      },
                  }
              });

            app.Use(async (context, next) =>
            {

                var token = context.Request.Headers.Get("Authorization")?.Replace("Bearer ", "");
                if (!string.IsNullOrEmpty(token))
                {
                    await next.Invoke();
                    return;
                }

                if (context.Request.Path.Value.ToLower().StartsWith("/error"))
                {
                    await next.Invoke();
                    return;
                }

                if (context.Request.Path.Value.ToLower().StartsWith("/scripts") ||
                    context.Request.Path.Value.ToLower().StartsWith("/content") || context.Request.Path.Value.ToLower() == "/favicon.ico")
                {
                    await next.Invoke();
                    return;
                }

                var user = context.Authentication.User;

                if (context.Request.Path.Value.ToLower() == "/account/postsignout")
                {
                    RemoveLoginCookies(context);
                    context.Response.Redirect("/account/login");

                    return;
                }

                if (context.Request.Path.Value.ToLower() == "/account/resetpassword")
                {
                    string resetPasswordPolicy = ConfigurationManager.AppSettings["OpenIdAzureAdB2CResetPasswordPolicy"];
                    string redirectUri = $"{ConfigurationManager.AppSettings["OpenIdAzureAdB2CRedirectUri"]}";
                    string tenant = ConfigurationManager.AppSettings["OpenIdAzureAdB2CTenant"];
                    string clientId = ConfigurationManager.AppSettings["OpenIdAzureAdB2CClientId"];

                    // Build the URL for the password reset
                    string resetPasswordUrl = $"https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/oauth2/v2.0/authorize?p={resetPasswordPolicy}&client_id={clientId}&redirect_uri={redirectUri}&response_type=id_token&scope={ConfigurationManager.AppSettings["OpenIdAzureAdB2CClientScopes"]}&nonce=defaultNonce";

                    // Redirect the user to Azure AD B2C password reset page
                    context.Response.Redirect(resetPasswordUrl);
                    return;
                }

                if (context.Request.Path.Value.ToLower() == "/account/signout")
                {
                    if (!user.Identity.IsAuthenticated)
                    {
                        context.Response.Redirect("/account/postsignout");
                        return;
                    }

                    var idpCookie = context.Request.Cookies[IdentityProviderCookieKey];

                    if (idpCookie == null && (user == null || !user.HasClaim(i => i.Type == OwinModuleStartup.IdentityProviderCookieKey)))
                    {
                        context.Response.Redirect("/");

                        await next.Invoke();
                        return;
                    }

                    string authType;

                    var idp = idpCookie ?? user.Claims.First(i => i.Type == OwinModuleStartup.IdentityProviderCookieKey).Value;

                    switch (idp)
                    {
                        case OwinModuleStartup.IdentityProviderCookieValueAAD:
                            authType = OpenIdConnectAuthenticationDefaults.AuthenticationType;
                            break;
                        case OwinModuleStartup.IdentityProviderCookieValueB2C:
                            authType = "AzureADB2C";
                            break;
                        default:
                            {
                                context.Response.Redirect("/");
                                await next.Invoke();
                                return;
                            };
                    }

                    context.Authentication.SignOut(new AuthenticationProperties() { RedirectUri = $"{context.Request.Scheme}://{context.Request.Host}/account/postsignout" }, authType, DefaultAuthenticationType);

                    await next.Invoke();
                    return;
                }

                if (user != null && !user.Identity.IsAuthenticated && context.Request.Cookies.Any(i => i.Key == IdentityProviderCookieKey) && context.Request.Path.Value.ToLower() != $"/account/SignInWithAzureAd".ToLower() &&
                    context.Request.Path.Value.ToLower() != $"/account/SignInWithAzureB2C".ToLower() && context.Request.Path.Value.ToLower() != $"/Account/SignSilentlyInWithAzureAd".ToLower() && context.Request.Path.Value.ToLower() != $"/Account/SignSilentlyInWithAzureAdB2c".ToLower())
                {
                    var isAjaxRequest = context.Request.Headers["X-Requested-With"] == "XMLHttpRequest";

                    if (isAjaxRequest)
                    {
                        // Unauthorized XMLHttpRequest detected
                        context.Response.StatusCode = 401;
                        return;
                    }

                    // Check if ID token is expired or close to expiring (custom logic)
                    var identityProvider = context.Request.Cookies[IdentityProviderCookieKey];

                    switch (identityProvider)
                    {
                        case IdentityProviderCookieValueAAD:
                            context.Response.Redirect($"{ConfigurationManager.AppSettings["OpenIdAzureAdSilentLogin"]}?redirect={UrlEncoder.Default.Encode(context.Request.Path.Value)}");
                            break;
                        case IdentityProviderCookieValueB2C:
                            context.Response.Redirect($"{ConfigurationManager.AppSettings["OpenIdAzureAdB2CSilentLogin"]}?redirect={UrlEncoder.Default.Encode(context.Request.Path.Value)}");
                            break;
                        default: goto case IdentityProviderCookieValueAAD;
                    }

                    return;
                }

                if (!user.Identity.IsAuthenticated && (context.Request.Path.Value.ToLower() != ConfigurationManager.AppSettings["OpenIdLoginRedirect"].ToLower() &&
                    context.Request.Path.Value.ToLower() != ConfigurationManager.AppSettings["OpenIdAzureAdSilentLogin"].ToLower() &&
                     context.Request.Path.Value.ToLower() != ConfigurationManager.AppSettings["OpenIdAzureAdB2CSilentLogin"].ToLower() &&
                     context.Request.Path.Value.ToLower() != "/account/SignInWithAzureAd".ToLower() &&
                      context.Request.Path.Value.ToLower() != "/account/SignInWithAzureB2C".ToLower()))
                {
                    if (IsAjaxRequest(context))
                    {
                        // Unauthorized XMLHttpRequest detected
                        context.Response.Headers.Append("X-ReauthState", "NoActiveProviderSession");
                        context.Response.StatusCode = 401;
                        return;
                    }
                    context.Response.Redirect(ConfigurationManager.AppSettings["OpenIdLoginRedirect"]);
                    return;
                }

                await next.Invoke();
            });
        }

        private static void RemoveLoginCookies(IOwinContext context)
        {
            context.Response.Cookies.Append(IdentityProviderCookieKey, string.Empty, new CookieOptions() { Expires = DateTime.UtcNow.AddYears(-10), SameSite = SameSiteMode.Lax, HttpOnly = true, Secure = context.Request.IsSecure }); // Add the cookie to the response

            context.Response.Cookies.Append("ASP.NET_SessionId", "", new CookieOptions() { Expires = DateTime.UtcNow.AddDays(-1), SameSite = SameSiteMode.Lax, HttpOnly = true, Secure = context.Request.IsSecure }); // Add the cookie to the response

            context.Response.Cookies.Append(IdentityProviderLoginHintCookieKey, "", new CookieOptions() { Expires = DateTime.UtcNow.AddDays(-1), SameSite = SameSiteMode.Lax, HttpOnly = true, Secure = context.Request.IsSecure }); // Add the cookie to the response
        }

        private static bool IsAjaxRequest(IOwinContext context)
        {
            return context.Request.Headers["X-Requested-With"] == "XMLHttpRequest";
        }
    }
}