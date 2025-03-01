using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;

namespace Mvc5AuzreAd.Controllers
{
    public class AccountController : Controller
    {
        [AllowAnonymous]
        public ActionResult SignInWithAzureAd()
        {
            if (User.Identity.IsAuthenticated)
            {
                return Redirect("/");
            }

            HttpContext.GetOwinContext().Authentication.Challenge(
                new AuthenticationProperties { RedirectUri = "/" },
                OpenIdConnectAuthenticationDefaults.AuthenticationType);

            return new HttpStatusCodeResult(401);
        }

        [AllowAnonymous]
        public void SignSilentlyInWithAzureAd(string redirect)
        {
            if (User.Identity.IsAuthenticated)
            {
                return;
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = redirect,
                Dictionary =
                {
                    ["prompt"] = "none",
                }
            };

            var loginHint = Request.Cookies[OwinModuleStartup.IdentityProviderLoginHintCookieKey]?.Value;

            if (!string.IsNullOrEmpty(loginHint))
            {
                properties.Dictionary.Add("login_hint", loginHint);
            }

            HttpContext.GetOwinContext().Authentication.Challenge(properties,
                OpenIdConnectAuthenticationDefaults.AuthenticationType);
        }

        [AllowAnonymous]
        // Sign in using Azure AD B2C
        public ActionResult SignInWithAzureB2C()
        {
            if (User.Identity.IsAuthenticated)
            {
                return Redirect("/");
            }

            HttpContext.GetOwinContext().Authentication.Challenge(
                new AuthenticationProperties { RedirectUri = "/" },
                "AzureADB2C");

            return new HttpStatusCodeResult(401);
        }

        [AllowAnonymous]
        public void SignSilentlyInWithAzureAdB2c(string redirect)
        {
            if (User.Identity.IsAuthenticated)
            {
                return;
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = redirect,
                Dictionary =
                {
                    ["prompt"] = "none",
                }
            };

            var loginHint = Request.Cookies[OwinModuleStartup.IdentityProviderLoginHintCookieKey]?.Value;

            if (!string.IsNullOrEmpty(loginHint))
            {
                properties.Dictionary.Add("login_hint", loginHint);
            }

            HttpContext.GetOwinContext().Authentication.Challenge(properties,
                "AzureADB2C");
        }

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                if (Request.IsAjaxRequest())
                {
                    return new HttpStatusCodeResult(HttpStatusCode.NoContent);
                }

                if (!string.IsNullOrEmpty(returnUrl))
                {
                    return Redirect(returnUrl);
                }
                // Redirect authenticated users to the homepage
                return RedirectToAction("Index", "Home");
            }

            if (Request.IsAjaxRequest())
            {
                return new HttpStatusCodeResult(401);
            }

            return View();
        }
    }
}