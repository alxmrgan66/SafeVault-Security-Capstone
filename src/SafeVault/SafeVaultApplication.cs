using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http.Features;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault;

public static class SafeVaultApplication
{
    public static WebApplication Build(string[] args, string? contentRoot = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = contentRoot,
            ApplicationName = typeof(SafeVaultApplication).Assembly.GetName().Name
        });
        if (builder.Configuration["urls"] is null)
        {
            builder.WebHost.UseUrls("http://127.0.0.1:5059");
        }
        builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 16 * 1024);

        builder.Services.AddRazorPages();
        builder.Services.Configure<FormOptions>(options =>
        {
            options.ValueCountLimit = 24;
            options.ValueLengthLimit = 1024;
            options.KeyLengthLimit = 128;
        });
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(services =>
        {
            var configuration = services.GetRequiredService<IConfiguration>();
            var environment = services.GetRequiredService<IWebHostEnvironment>();
            var path = configuration["SafeVault:DatabasePath"]
                ?? Path.Combine(environment.ContentRootPath, "data", "safevault.sqlite");
            return new AccountStore(path);
        });
        builder.Services.AddScoped<AccountSessions>();
        builder.Services.AddScoped<VaultCookieEvents>();
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Login";
                options.Cookie.Name = "SafeVault.Session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.ExpireTimeSpan = AccountSessions.Lifetime;
                options.SlidingExpiration = false;
                options.EventsType = typeof(VaultCookieEvents);
            });
        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery(options => options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest);
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy("account-forms", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "local",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1) }));
        });

        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers["Content-Security-Policy"] =
                "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
            headers["X-Content-Type-Options"] = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Cache-Control"] = "no-store";
            await next(context);
        });
        app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
        {
            var error = context.Features.Get<IExceptionHandlerFeature>()?.Error;
            context.Response.StatusCode = error is BadHttpRequestException badRequest
                ? badRequest.StatusCode
                : StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync(error is BadHttpRequestException
                ? "The request could not be processed."
                : "An internal error occurred.");
        }));
        app.UseStaticFiles();
        app.UseRouting();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapRazorPages();
        return app;
    }
}
