# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

COPY src/Authentication.Api/Authentication.Api.csproj src/Authentication.Api/
COPY src/Authentication.Application/Authentication.Application.csproj src/Authentication.Application/
COPY src/Authentication.Domain/Authentication.Domain.csproj src/Authentication.Domain/
COPY src/Authentication.Infrastructure/Authentication.Infrastructure.csproj src/Authentication.Infrastructure/

RUN dotnet restore src/Authentication.Api/Authentication.Api.csproj

COPY src/ src/

RUN dotnet publish src/Authentication.Api/Authentication.Api.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false


# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

WORKDIR /app

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_HTTP_PORTS=8080

EXPOSE 8080

COPY --from=build /app/publish .

USER app

ENTRYPOINT ["dotnet", "Authentication.Api.dll"]