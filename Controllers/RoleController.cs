using authServer.Data;
using authServer.Entities;
using authServer.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace authServer.Controllers;
[ApiExplorerSettings(IgnoreApi = true)]
[Authorize(Policy = ApplicationConstants.Policy.IsSystem)]
public class RoleController : Controller
{
    private readonly RoleManager<ApplicationRole> _roleManager;

    private readonly IMapper _mapper;
    private readonly ILogger<ScopeController> _logger;

    public RoleController(RoleManager<ApplicationRole> roleManager,
        IMapper mapper, ILogger<ScopeController> logger)
    {
        _roleManager = roleManager;
        _mapper = mapper;
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View(_roleManager.Roles.ToList());
    }

    [HttpGet]
    public IActionResult View(Guid id)
    {
        var role = _roleManager.Roles.FirstOrDefault(x => x.Id == id);
        if (role == null) return NotFound();

        ViewBag.Role = role;

        return View(role);
    }

    [HttpGet]
    public IActionResult Add()
    {
        return View(new RoleInputModel());
    }

    [HttpPost]
    public async Task<IActionResult> AddAsync(RoleInputModel input)
    {
        if (!ModelState.IsValid) return View(input);

        var descriptor = new ApplicationRole()
        {
            Name = input.Name,
            Description = input.Description
        };
        var result = await _roleManager.CreateAsync(descriptor);
        var role = _roleManager.Roles.FirstOrDefault(x => x.Name == descriptor.Name);

        _logger.LogInformation("{user} created new role {role}", User.Identity.Name, role.Name);
        return RedirectToAction("View", new { id = role.Id });
    }

    [HttpGet]
    public IActionResult Edit(Guid id)
    {
        var role = _roleManager.Roles.FirstOrDefault(x => x.Id == id);
        if (role == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();

        ViewBag.Role = role;

        return View(_mapper.Map<RoleInputModel>(role));
    }

    [HttpPost]
    public async Task<IActionResult> EditAsync(Guid id, ScopeInputModel input)
    {
        if (!ModelState.IsValid) return View(input);

        var role = _roleManager.Roles.FirstOrDefault(x => x.Id == id);
        if (role == null) return NotFound();

        role.Name = input.Name;
        role.NormalizedName = input.Name.ToUpper();
        role.Description = input.Description;

        await _roleManager.UpdateAsync(role);
        _logger.LogInformation("{user} updated role {role}", User.Identity.Name, role.Name);

        return RedirectToAction("View", new { id });
    }

    [HttpGet]
    public async Task<IActionResult> DeleteAsync(Guid id)
    {
        var role = _roleManager.Roles.FirstOrDefault(x => x.Id == id);
        if (role == null) return NotFound();

        await _roleManager.DeleteAsync(role);
        _logger.LogInformation("{user} deleted role {role}", User.Identity.Name, id);

        return RedirectToAction("Index");
    }
}