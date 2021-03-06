// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Identity.Test;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.DependencyInjection.Fallback;
using Microsoft.Framework.OptionsModel;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.AspNet.Identity.InMemory.Test
{
    public class StartupTest
    {
        public class ApplicationUser : IdentityUser { }

        [Fact]
        public async Task EnsureStartupUsageWorks()
        {
            var builder = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());

            builder.UseServices(services => services.AddIdentity<ApplicationUser>().AddInMemory());

            var userStore = builder.ApplicationServices.GetRequiredService<IUserStore<ApplicationUser>>();
            var roleStore = builder.ApplicationServices.GetRequiredService<IRoleStore<IdentityRole>>();
            var userManager = builder.ApplicationServices.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = builder.ApplicationServices.GetRequiredService<RoleManager<IdentityRole>>();

            Assert.NotNull(userStore);
            Assert.NotNull(userManager);
            Assert.NotNull(roleStore);
            Assert.NotNull(roleManager);

            await CreateAdminUser(builder.ApplicationServices);
        }

        [Fact]
        public void VerifyUseInMemoryLifetimes()
        {
            var builder = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());
            builder.UseServices(services => services.AddIdentity<ApplicationUser>().AddInMemory());

            var userStore = builder.ApplicationServices.GetRequiredService<IUserStore<ApplicationUser>>();
            var roleStore = builder.ApplicationServices.GetRequiredService<IRoleStore<IdentityRole>>();
            var userManager = builder.ApplicationServices.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = builder.ApplicationServices.GetRequiredService<RoleManager<IdentityRole>>();

            Assert.NotNull(userStore);
            Assert.NotNull(userManager);
            Assert.NotNull(roleStore);
            Assert.NotNull(roleManager);

            var userStore2 = builder.ApplicationServices.GetRequiredService<IUserStore<ApplicationUser>>();
            var roleStore2 = builder.ApplicationServices.GetRequiredService<IRoleStore<IdentityRole>>();
            var userManager2 = builder.ApplicationServices.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager2 = builder.ApplicationServices.GetRequiredService<RoleManager<IdentityRole>>();

            // Stores are singleton, managers are scoped
            Assert.Equal(userStore, userStore2);
            Assert.Equal(userManager, userManager2);
            Assert.Equal(roleStore, roleStore2);
            Assert.Equal(roleManager, roleManager2);
        }


        private static async Task CreateAdminUser(IServiceProvider serviceProvider)
        {
            const string userName = "admin";
            const string roleName = "Admins";
            const string password = "1qaz@WSX";
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            var user = new ApplicationUser { UserName = userName };
            IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user, password));
            IdentityResultAssert.IsSuccess(await roleManager.CreateAsync(new IdentityRole { Name = roleName }));
            IdentityResultAssert.IsSuccess(await userManager.AddToRoleAsync(user, roleName));
        }
    }
}