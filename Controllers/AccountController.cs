using authServer.Entities;
using authServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace authServer.Controllers;
[ApiExplorerSettings(IgnoreApi = true)]
public class AccountController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<AccountController> _logger;

    public AccountController(SignInManager<ApplicationUser> signInManager, ILogger<AccountController> logger)
    {
        _signInManager = signInManager;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View(new LoginInputModel());
    }

    [HttpPost]
    public async Task<IActionResult> LoginAsync(LoginInputModel input, string returnUrl)
    {
        if (!ModelState.IsValid) return View(input);

        returnUrl ??= Url.Content("~/");

        var result = await _signInManager.PasswordSignInAsync(input.Username, input.Password, input.RememberMe, lockoutOnFailure: true);
        if (result.Succeeded)
        {
            _logger.LogInformation("{user} signed in", input.Username);
            return Redirect(returnUrl);
        }
        else
        {
            _logger.LogInformation("{user} failed to log in. LockedOut: {lockedOut}; NotAllowed: {notAllowed}",
                input.Username, result.IsLockedOut, result.IsNotAllowed);
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(input);
        }
    }

    public async Task<IActionResult> LogoutAsync(string returnUrl)
    {
        var name = User.Identity.Name;
        await _signInManager.SignOutAsync();
        _logger.LogInformation("{user} signed out", name);
        return LocalRedirect(returnUrl ?? Url.Content("~/"));
    }

    public IActionResult AccessDenied()
    {
        return View();
    }

    [Authorize]
    public IActionResult Profile()
    {
        return View();
    }
}
