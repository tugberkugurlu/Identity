// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNet.Identity.Test;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.DependencyInjection.Fallback;
using Xunit;

namespace Microsoft.AspNet.Identity.EntityFramework.Test
{
    public class GuidUser : IdentityUser<Guid>
    {
        public GuidUser()
        {
            Id = Guid.NewGuid();
            UserName = Id.ToString();
        }
    }

    public class GuidRole : IdentityRole<Guid>
    {
        public GuidRole()
        {
            Id = Guid.NewGuid();
            Name = Id.ToString();
        }
    }

    [TestCaseOrderer("Microsoft.AspNet.Identity.Test.PriorityOrderer", "Microsoft.AspNet.Identity.EntityFramework.Test")]
    public class UserStoreGuidTest : SqlStoreTestBase<GuidUser, GuidRole, Guid>
    {
        private readonly string _connectionString = @"Server=(localdb)\v11.0;Database=SqlUserStoreGuidTest" + DateTime.Now.Month + "-" + DateTime.Now.Day + "-" + DateTime.Now.Year + ";Trusted_Connection=True;";

        public override string ConnectionString
        {
            get
            {
                return _connectionString;
            }
        }

        public class ApplicationUserStore : UserStore<GuidUser, GuidRole, TestDbContext, Guid>
        {
            public ApplicationUserStore(TestDbContext context) : base(context) { }

            public override Guid ConvertIdFromString(string userId)
            {
                return new Guid(userId);
            }
        }

        public class ApplicationRoleStore : RoleStore<GuidRole, TestDbContext, Guid>
        {
            public ApplicationRoleStore(TestDbContext context) : base(context) { }

            public override Guid ConvertIdFromString(string id)
            {
                return new Guid(id);
            }
        }

        protected override UserManager<GuidUser> CreateManager(object context)
        {
            if (context == null)
            {
                context = CreateTestContext();
            }
            return MockHelpers.CreateManager(new ApplicationUserStore((TestDbContext)context));
        }

        protected override RoleManager<GuidRole> CreateRoleManager(object context)
        {
            if (context == null)
            {
                context = CreateTestContext();
            }
            var services = DbUtil.ConfigureDbServices(ConnectionString);
            services.AddIdentity<GuidUser, GuidRole>().AddRoleStore(new ApplicationRoleStore((TestDbContext)context));
            return services.BuildServiceProvider().GetRequiredService<RoleManager<GuidRole>>();
        }
    }
}