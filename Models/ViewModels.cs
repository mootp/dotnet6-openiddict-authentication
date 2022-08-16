using System.ComponentModel.DataAnnotations;

namespace authServer.Models;

public class StatusViewModel
{
    public string Subject { get; set; }
    public string Message { get; set; }
}

public class ErrorViewModel
{
    public string Subject { get; set; }
    public string Message { get; set; }
}

public class AuthorizeViewModel
{
    [Display(Name = "Application")]
    public string ApplicationName { get; set; }

    [Display(Name = "Scope")]
    public string Scope { get; set; }
}

public class LoginInputModel
{
    [Required]
    public string Username { get; set; }

    [Required, DataType(DataType.Password)]
    public string Password { get; set; }

    [Display(Name = "Remember me")]
    public bool RememberMe { get; set; }
}

public class RegistrationInputModel
{
    [Required, MaxLength(255), Display(Name = "First Name")]
    public string FirstName { get; set; }

    [Required, MaxLength(255), Display(Name = "Last Name")]
    public string LastName { get; set; }

    [Required]
    public string Username { get; set; }

    [Required, EmailAddress]
    public string Email { get; set; }

    [Required, DataType(DataType.Password)]
    public string Password { get; set; }

    [Required, DataType(DataType.Password), Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }
}

public class ApplicationInputModel
{
    [Display(Name = "Display Name")]
    public string DisplayName { get; set; }

    [Required, MaxLength(100), Display(Name = "Client Id")]
    public string ClientId { get; set; }

    [Display(Name = "Client Secret")]
    public string ClientSecret { get; set; }

    [Display(Name = "Redirect URIs")]
    public string RedirectUris { get; set; }

    [Display(Name = "Post-Logout Redirect URIs")]
    public string PostLogoutRedirectUris { get; set; }

    public bool IsNewClientSecret { get; set; }

    [Display(Name = "PKCE")]
    public bool IsPkce { get; set; } = true;
}

public class ScopeInputModel
{
    [Required, MaxLength(200)]
    public string Name { get; set; }

    [Display(Name = "Display Name")]
    public string DisplayName { get; set; }

    public string Description { get; set; }
}

public class EditUserInputModel
{
    public string Id { get; set; }

    [MaxLength(255), Display(Name = "First Name")]
    public string FirstName { get; set; }

    [MaxLength(255), Display(Name = "Last Name")]
    public string LastName { get; set; }

    [EmailAddress]
    public string Email { get; set; }

    [DataType(DataType.Password), Display(Name = "New Password")]
    public string NewPassword { get; set; }

    [DataType(DataType.Password), Display(Name = "Confirm New Password")]
    [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmNewPassword { get; set; }

    [Display(Name = "Email Confirmed")]
    public bool EmailConfirmed { get; set; }

    public string DisplayName => $"{FirstName} {LastName}";
}

public class RoleInputModel
{
    [Required, MaxLength(200)]
    public string Name { get; set; }
    public string Description { get; set; }
}