namespace Net8Angular17.Models
{
    public class AuthResponseModel
    {
        public string? Token { get; set; } = string.Empty;
        public bool IsSuccess { get; set; }
        public string? Message { get; set; }
    }
}