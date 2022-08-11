using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace authServer.ViewModels;

public class LogoutViewModel
{
    [BindNever]
    public string? RequestId { get; set; }
}