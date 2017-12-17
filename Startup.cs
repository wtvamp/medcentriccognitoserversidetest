using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace med_centric_credit_2._0_demo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthorization(auth =>
            {
                auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder()   
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser()
                    .Build());
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme‌​;
            }).AddJwtBearer(options => 
            {
                options.TokenValidationParameters = this.TokenValidationParameters("https://cognito-idp.us-west-2.amazonaws.com/us-west-2_AZBRd5hvY");
            });
               
            services.AddMvc();

            	

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseMvc();
        }

        public RsaSecurityKey SigningKey(string Key, string Expo)
        {
                RSA rrr = RSA.Create();

                rrr.ImportParameters(
                    new RSAParameters()
                    {
                        Modulus =  Base64UrlEncoder.DecodeBytes(Key),
                        Exponent = Base64UrlEncoder.DecodeBytes(Expo)
                    }
                );
    
                return new RsaSecurityKey(rrr);  
        }

        public TokenValidationParameters TokenValidationParameters(string issuer)
        {
                // Basic settings - signing key to validate with, audience and issuer.
                return new TokenValidationParameters
                {
                    // Basic settings - signing key to validate with, IssuerSigningKey and issuer.
                    IssuerSigningKey = this.SigningKey("syeo-lxVf3AscpcLm0WgYv0hcbhZtYa9ANxmD_KBkxpaOWM-8O62akcHGP8DIwkaIp0owrUm_lR9an2JqcnfBSTSfHKlbESwPlhSzCMt1VJx9KOwv_RRMAnoCTWKG7tujEav60B3GBSdLcMoNjvuYPbCNtGPqM_90ruvfi27pyDnT5xJzyDT324IYXRfuxpPWw-zsJjGA4sK3-YWOwbpSvxo7qM1rvzMtqNrnslhmzk_bEdxXtaUjkXdR3HDNyPmjAd74_JrXsZrb-jKygHSj4XjZXiRph9-QDh42gKv9qelwD8429--hk_rDrcHwq5Wi5dxM0A7XcwM6Ph_s9u5nQ","AQAB"),
                    ValidIssuer      = issuer,
                        
                    // when receiving a token, check that the signing key
                    ValidateIssuerSigningKey = true,
    
                    // When receiving a token, check that we've signed it.
                    ValidateIssuer = true,
    
                    // When receiving a token, check that it is still valid.
                    ValidateLifetime = true,
                        
                    // Do not validate Audience on the "access" token since Cognito does not supply it but it is      on the "id"
                    ValidateAudience = false,
    
                    // This defines the maximum allowable clock skew - i.e. provides a tolerance on the token expiry time 
                    // when validating the lifetime. As we're creating the tokens locally and validating them on the same 
                    // machines which should have synchronised time, this can be set to zero. Where external tokens are
                    // used, some leeway here could be useful.
                    ClockSkew = TimeSpan.FromMinutes(0)
                };
            
        }
    }
}
