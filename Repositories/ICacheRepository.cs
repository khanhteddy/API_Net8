namespace Net8Angular17.Repositories;

public interface ICacheRepository
{
    T GetData<T>(string key);
    bool SetData<T>(string key, T value, DateTimeOffset expirationTime);
    object RemoveData(string key);
    public IEnumerable<string> GetAllKeys(string pattern);
    public void SetData1(string key, string value);
    public string GetData1(string key);
}