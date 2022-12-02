using Learn.AuthCode;

var builder = WebApplication.CreateBuilder(args);

builder.ConfgureService();
builder.ConfigureAuth();
var app = builder.Build();

app.Configure();

app.Run();
