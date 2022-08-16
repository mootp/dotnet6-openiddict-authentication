using System.Security.Claims;
using authServer.Data;
using authServer.Entities;
using authServer.Models;
using authServer.Services;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace authServer.Controllers;
[ApiExplorerSettings(IgnoreApi = true)]
[Authorize(Policy = ApplicationConstants.Policy.IsSystem)]
public class UserController : Controller
{
    private readonly UserService _userService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;

    private readonly IMapper _mapper;
    private readonly ILogger<UserController> _logger;

    public UserController(UserService userService, UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, IMapper mapper,
        ILogger<UserController> logger)
    {
        _userService = userService;
        _userManager = userManager;
        _roleManager = roleManager;
        _mapper = mapper;
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View(_userService.GetUsers());
    }

    public async Task<IActionResult> ViewAsync(Guid id)
    {
        var user = _userService.GetUser(id);
        if (user == null) return NotFound();
        var claims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);
        var allRoles = _roleManager.Roles.Select(x => x.Name).ToList();
        var availableRoles = allRoles.Where(s => !roles.Contains(s));

        ViewBag.Claims = claims;
        ViewBag.Roles = roles;
        ViewBag.AvailableRoles = availableRoles;

        return View(user);
    }

    [HttpGet]
    public IActionResult Add()
    {
        return View(new RegistrationInputModel());
    }

    [HttpPost]
    public async Task<IActionResult> AddAsync(RegistrationInputModel input)
    {
        if (!ModelState.IsValid) return View(input);

        var user = _mapper.Map<ApplicationUser>(input);
        // user.UserName = input.Email;
        // user.DisplayName = $"{input.FirstName} {input.LastName}";
        user.EmailConfirmed = true;
        var result = await _userManager.CreateAsync(user, input.Password);
        if (result.Succeeded)
        {
            _logger.LogInformation("{user} created account for {newUser}", User.Identity.Name, input.Email);
            return RedirectToAction("View", new { id = user.Id });
        }
        else
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);
            return View(input);
        }
    }

    [HttpGet]
    public async Task<IActionResult> EditAsync(Guid id)
    {
        var user = _userService.GetUser(id);
        if (user == null) return NotFound();
        var claims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);
        var allRoles = _roleManager.Roles.Select(x => x.Name).ToList();
        var availableRoles = allRoles.Where(s => !roles.Contains(s));

        ViewBag.Claims = claims;
        ViewBag.Roles = roles;
        ViewBag.AvailableRoles = availableRoles;

        return View(_mapper.Map<EditUserInputModel>(user));
    }

    [HttpPost]
    public async Task<IActionResult> EditAsync(Guid id, EditUserInputModel input)
    {
        if (!ModelState.IsValid) return View(input);

        var user = _userService.GetUser(id);

        if (!string.IsNullOrWhiteSpace(input.NewPassword))
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("Password", error.Description);
                return View(input);
            }
        }

        user.EmailConfirmed = input.EmailConfirmed;
        if (!string.IsNullOrWhiteSpace(input.FirstName))
            user.FirstName = input.FirstName;
        if (!string.IsNullOrWhiteSpace(input.LastName))
            user.LastName = input.LastName;

        _userService.SaveChanges();

        _logger.LogInformation("{user} edited account {account}", User.Identity.Name, input.Email);

        return RedirectToAction("View", new { id = user.Id });
    }

    public async Task<IActionResult> AddClaimAsync(Guid userId, string claimType, string claimValue)
    {
        var user = _userService.GetUser(userId);
        var result = await _userManager.AddClaimAsync(user, new Claim(claimType, claimValue));
        if (result.Succeeded)
        {
            _logger.LogError("{user} added claim {claimType}={claimValue} to {account}",
                User.Identity.Name, claimType, claimValue, userId);
        }
        else
        {
            _logger.LogError("Failed to add claim {claimType}={claimValue} to {account}: {errors}",
                    claimType, claimValue, userId, result.Errors);
        }
        return RedirectToAction("View", new { id = userId });
    }

    public async Task<IActionResult> RemoveClaimAsync(Guid userId, string claimType, string claimValue)
    {
        var user = _userService.GetUser(userId);
        var result = await _userManager.RemoveClaimAsync(user, new Claim(claimType, claimValue));
        if (result.Succeeded)
        {
            _logger.LogError("{user} removed claim {claimType}={claimValue} from {account}",
                User.Identity.Name, claimType, claimValue, userId);
        }
        else
        {
            _logger.LogError("Failed to remove claim {claimType}={claimValue} from {account}: {errors}",
                    claimType, claimValue, userId, result.Errors);
        }
        return RedirectToAction("View", new { id = userId });
    }

    public async Task<IActionResult> AddRoleAsync(Guid userId, string role)
    {
        var user = _userService.GetUser(userId);
        var result = await _userManager.AddToRoleAsync(user, role);
        if (result.Succeeded)
        {
            _logger.LogError("{user} added claim {role} to {account}",
                User.Identity.Name, role, userId);
        }
        else
        {
            _logger.LogError("Failed to add claim {role} to {account}: {errors}",
                    role, userId, result.Errors);
        }
        return RedirectToAction("View", new { id = userId });
    }

    public async Task<IActionResult> RemoveRoleAsync(Guid userId, string role)
    {
        var user = _userService.GetUser(userId);
        var result = await _userManager.RemoveFromRoleAsync(user, role);
        if (result.Succeeded)
        {
            _logger.LogError("{user} removed role {role} from {account}",
                User.Identity.Name, role, userId);
        }
        else
        {
            _logger.LogError("Failed to remove role {role} from {account}: {errors}",
                    role, userId, result.Errors);
        }
        return RedirectToAction("View", new { id = userId });
    }
}

