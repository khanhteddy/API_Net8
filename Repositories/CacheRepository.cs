

using System.Text.Json;
using StackExchange.Redis;

namespace Net8Angular17.Repositories;

public class CacheRepository: ICacheRepository
{
    private IDatabase _cacheDB;
    private readonly ConnectionMultiplexer _redis;
    public CacheRepository()
    {
        try
        {
            var options = ConfigurationOptions.Parse("localhost:6379");
            options.ConnectRetry = 5;  // Number of retry attempts
            options.ConnectTimeout = 5000;  // Connection timeout in milliseconds
            options.SyncTimeout = 5000;  // Sync operation timeout in milliseconds

            options.AbortOnConnectFail = false; // Allow retrying connection
            _redis = ConnectionMultiplexer.Connect(options);
            _cacheDB = _redis.GetDatabase();
        }
        catch (RedisConnectionException ex)
        {
            // Log the exception and handle it as needed
            Console.WriteLine($"Redis connection failed: {ex.Message}");
            throw;
        }
    }
    public T GetData<T>(string key)
    {
        var value = _cacheDB.StringGet(key);
        if (!string.IsNullOrEmpty(value))
        {
            return JsonSerializer.Deserialize<T>(value);
        }

        return default;
    }

    public bool SetData<T>(string key, T value, DateTimeOffset expirationTime)
    {
        var expirtyTime = expirationTime.DateTime.Subtract(DateTime.Now);
        return _cacheDB.StringSet(key, JsonSerializer.Serialize(value), expirtyTime);
    }

    public object RemoveData(string key)
    {
        var _exist = _cacheDB.KeyExists(key);
        if (_exist)
        {
            return _cacheDB.KeyDelete(key);
        }

        return false;
    }
    public IEnumerable<string> GetAllKeys(string pattern = "*")
    {
        var server = _redis.GetServer("localhost:6379");
        return server.Keys(pattern: pattern).Select(key => (string)key);
    }
    public void SetData1(string key, string value)
    {
        _cacheDB.StringSet(key, value);
    }

    public string GetData1(string key)
    {
        return _cacheDB.StringGet(key);
    }
}