using Microsoft.AspNet.Builder;
using Microsoft.Framework.Configuration;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Dnx.Runtime;
using Microsoft.AspNet.Identity;
using Microsoft.Framework.DependencyInjection.Extensions;
using System.Threading.Tasks;
using System.Security.Claims;
using System;
using Microsoft.Framework.OptionsModel;
using Dnx.Identity.MongoDB;
using MongoDB.Driver;
#if DNX452
using NLog.Config;
using NLog.Targets;
#endif

namespace IdentitySamples
{
    public partial class Startup
    {
        public Startup(IApplicationEnvironment env)
        {
            /*
            * Below code demonstrates usage of multiple configuration sources. For instance a setting say 'setting1' is found in both the registered sources,
            * then the later source will win. By this way a Local config can be overridden by a different setting while deployed remotely.
            */
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ApplicationBasePath)
                .AddJsonFile("LocalConfig.json")
                .AddEnvironmentVariables(); //All environment variables in the process's context flow in as configuration values.

            Configuration = builder.Build();
        }

        public IConfiguration Configuration { get; private set; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IUserStore<MongoIdentityUser>>(provider =>
            {
                var client = new MongoClient();
                var database = client.GetDatabase("IdentitySampleMvc");
                var loggerFactory = provider.GetService(typeof(ILoggerFactory)) as ILoggerFactory;

                return new MongoUserStore<MongoIdentityUser>(database, loggerFactory);
            });

            services.AddOptions();
            services.AddAuthentication(options =>
            {
                // This is the Default value for ExternalCookieAuthenticationScheme
                options.SignInScheme = new IdentityCookieOptions().ExternalCookieAuthenticationScheme;
            });

            // Identity services
            services.TryAddSingleton<IdentityMarkerService>();
            services.TryAddScoped<IUserValidator<MongoIdentityUser>, UserValidator<MongoIdentityUser>>();
            services.TryAddScoped<IPasswordValidator<MongoIdentityUser>, PasswordValidator<MongoIdentityUser>>();
            services.TryAddScoped<IPasswordHasher<MongoIdentityUser>, PasswordHasher<MongoIdentityUser>>();
            services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            services.TryAddScoped<IdentityErrorDescriber>();
            services.TryAddScoped<ISecurityStampValidator, SecurityStampValidator<MongoIdentityUser>>();
            services.TryAddScoped<IUserClaimsPrincipalFactory<MongoIdentityUser>, UserClaimsPrincipalFactory<MongoIdentityUser>>();
            services.TryAddScoped<UserManager<MongoIdentityUser>, UserManager<MongoIdentityUser>>();
            services.TryAddScoped<SignInManager<MongoIdentityUser>, SignInManager<MongoIdentityUser>>();

            AddDefaultTokenProviders(services);

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
#if DNX452
            var config = new LoggingConfiguration();

            // Step 2. Create targets and add them to the configuration
            var consoleTarget = new ColoredConsoleTarget();
            config.AddTarget("console", consoleTarget);
            consoleTarget.Layout = @"${date:format=HH\\:MM\\:ss} ${ndc} ${logger} ${message} ";
            var rule1 = new LoggingRule("*", NLog.LogLevel.Debug, consoleTarget);
            config.LoggingRules.Add(rule1);

            loggerFactory.AddNLog(new global::NLog.LogFactory(config));
#endif
            app.UseDeveloperExceptionPage()
               .UseStaticFiles()
               .UseIdentity()
               .UseFacebookAuthentication(options =>
               {
                   options.AppId = "901611409868059";
                   options.AppSecret = "4aa3c530297b1dcebc8860334b39668b";
               })
               .UseGoogleAuthentication(options =>
               {
                   options.ClientId = "514485782433-fr3ml6sq0imvhi8a7qir0nb46oumtgn9.apps.googleusercontent.com";
                   options.ClientSecret = "V2nDD9SkFbvLTqAUBWBBxYAL";
               })
               .UseTwitterAuthentication(options =>
               {
                   options.ConsumerKey = "BSdJJ0CrDuvEhpkchnukXZBUv";
                   options.ConsumerSecret = "xKUNuKhsRdHD03eLn67xhPAyE1wFFEndFo1X2UJaK2m1jdAxf4";
               })
               .UseMvc(routes =>
                {
                    routes.MapRoute(
                        name: "default",
                        template: "{controller}/{action}/{id?}",
                        defaults: new { controller = "Home", action = "Index" });
                });
        }

        public virtual void AddDefaultTokenProviders(IServiceCollection services)
        {
            var dataProtectionProviderType = typeof(DataProtectorTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            var phoneNumberProviderType = typeof(PhoneNumberTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            var emailTokenProviderType = typeof(EmailTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            AddTokenProvider(services, TokenOptions.DefaultProvider, dataProtectionProviderType);
            AddTokenProvider(services, TokenOptions.DefaultEmailProvider, emailTokenProviderType);
            AddTokenProvider(services, TokenOptions.DefaultPhoneProvider, phoneNumberProviderType);
        }

        private void AddTokenProvider(IServiceCollection services, string providerName, Type provider)
        {
            services.Configure<IdentityOptions>(options =>
            {
                options.Tokens.ProviderMap[providerName] = new TokenProviderDescriptor(provider);
            });

            services.AddTransient(provider);
        }
    }

    public class UserClaimsPrincipalFactory<TUser> : IUserClaimsPrincipalFactory<TUser>
        where TUser : class
    {
        public UserClaimsPrincipalFactory(
            UserManager<TUser> userManager,
            IOptions<IdentityOptions> optionsAccessor)
        {
            if (userManager == null)
            {
                throw new ArgumentNullException(nameof(userManager));
            }
            if (optionsAccessor == null || optionsAccessor.Value == null)
            {
                throw new ArgumentNullException(nameof(optionsAccessor));
            }

            UserManager = userManager;
            Options = optionsAccessor.Value;
        }

        public UserManager<TUser> UserManager { get; private set; }

        public IdentityOptions Options { get; private set; }

        public virtual async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var userId = await UserManager.GetUserIdAsync(user);
            var userName = await UserManager.GetUserNameAsync(user);
            var id = new ClaimsIdentity(Options.Cookies.ApplicationCookieAuthenticationScheme,
                Options.ClaimsIdentity.UserNameClaimType,
                Options.ClaimsIdentity.RoleClaimType);
            id.AddClaim(new Claim(Options.ClaimsIdentity.UserIdClaimType, userId));
            id.AddClaim(new Claim(Options.ClaimsIdentity.UserNameClaimType, userName));
            if (UserManager.SupportsUserSecurityStamp)
            {
                id.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType,
                    await UserManager.GetSecurityStampAsync(user)));
            }
            if (UserManager.SupportsUserRole)
            {
                var roles = await UserManager.GetRolesAsync(user);
                foreach (var roleName in roles)
                {
                    id.AddClaim(new Claim(Options.ClaimsIdentity.RoleClaimType, roleName));
                }
            }
            if (UserManager.SupportsUserClaim)
            {
                id.AddClaims(await UserManager.GetClaimsAsync(user));
            }
            return new ClaimsPrincipal(id);
        }
    }
}
