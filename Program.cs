
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Net8Angular17.Data;
using Net8Angular17.Models;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("WebApiDatabase");
var JWTSetting = builder.Configuration.GetSection("JWT");
// Add services to the container.

builder.Services.AddDbContext<DataContext>(options => {
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
});

builder.Services.AddIdentity<AppUser,IdentityRole>().AddEntityFrameworkStores<DataContext>()
.AddDefaultTokenProviders();


builder.Services.AddSwaggerGen(c=>{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Book API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme{
        Description = @"JWT Authorization Example : 'Bearer eyeleieieekeieieie",
        Name = "Authorization",
        In = ParameterLocation.Header,
        //Type = SecuritySchemeType.ApiKey,
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement(){
        {
            // new OpenApiSecurityScheme{
            //     Reference = new OpenApiReference
            //     {
            //         Type = ReferenceType.SecurityScheme,
            //         Id = "Bearer"
            //     },
            //     Scheme = "outh2",
            //     Name="Bearer",
            //     In = ParameterLocation.Header,
            // },
            // new List<string>()
            new OpenApiSecurityScheme
			{
				Reference = new OpenApiReference
				{
					Type=ReferenceType.SecurityScheme,
					Id="Bearer"
				}
			},
			new string[]{}
        }
    });

});

builder.Services.AddAuthentication(opt=>{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(opt=>{
    opt.SaveToken = true;
    opt.RequireHttpsMetadata = false;
    opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime =true,
        ValidateIssuerSigningKey = true,
        ValidAudience  = JWTSetting["ValidAudience"],
        ValidIssuer=JWTSetting["ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWTSetting.GetSection("securityKey").Value!))


    };
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();


var app = builder.Build();
app.UseHttpsRedirection();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseCors(options =>
{
    options.AllowAnyHeader();
    options.AllowAnyMethod();
    options.AllowAnyOrigin();
});

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
