// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Security;
using Microsoft.AspNet.Identity.Test;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.DependencyInjection.Fallback;
using Moq;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.AspNet.Identity.InMemory.Test
{
    public class ApplicationUser : IdentityUser { }

    public class HttpSignInTest
    {
#if NET45
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task VerifyAccountControllerSignIn(bool isPersistent)
        {
            IBuilder app = new Builder.Builder(new ServiceCollection().BuildServiceProvider());
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie
            });

            var context = new Mock<HttpContext>();
            var response = new Mock<HttpResponse>();
            context.Setup(c => c.Response).Returns(response.Object).Verifiable();
            response.Setup(r => r.SignIn(It.IsAny<ClaimsIdentity>(), It.Is<AuthenticationProperties>(v => v.IsPersistent == isPersistent))).Verifiable();
            var contextAccessor = new Mock<IContextAccessor<HttpContext>>();
            contextAccessor.Setup(a => a.Value).Returns(context.Object);
            app.UseServices(services =>
            {
                services.AddInstance(contextAccessor.Object);
                services.AddIdentity<ApplicationUser, IdentityRole>(s =>
                {
                    s.AddInMemory();
                }).AddHttpSignIn();
            });

            // Act
            var user = new ApplicationUser
            {
                UserName = "Yolo"
            };
            const string password = "Yol0Sw@g!";
            var userManager = app.ApplicationServices.GetService<UserManager<ApplicationUser>>();
            var signInManager = app.ApplicationServices.GetService<SignInManager<ApplicationUser>>();

            IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user, password));
            var result = await signInManager.PasswordSignInAsync(user.UserName, password, isPersistent, false);

            // Assert
            Assert.Equal(SignInStatus.Success, result);
            context.VerifyAll();
            response.VerifyAll();
            contextAccessor.VerifyAll();
        }
#endif
    }
}