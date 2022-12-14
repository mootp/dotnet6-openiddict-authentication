using System.Text.Json;
using authServer.Data;
using authServer.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;

namespace authServer.Controllers;
[ApiExplorerSettings(IgnoreApi = true)]
[Authorize(Policy = ApplicationConstants.Policy.IsSystem)]
public class ScopeController : Controller
{
    private readonly OpenIddictScopeManager<OpenIddictEntityFrameworkCoreScope> _scopeManager;

    private readonly IMapper _mapper;
    private readonly ILogger<ScopeController> _logger;

    public ScopeController(OpenIddictScopeManager<OpenIddictEntityFrameworkCoreScope> scopeManager,
        IMapper mapper, ILogger<ScopeController> logger)
    {
        _scopeManager = scopeManager;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<IActionResult> IndexAsync()
    {
        return View(await _scopeManager.ListAsync().ToListAsync());
    }

    [HttpGet]
    public async Task<IActionResult> ViewAsync(string id)
    {
        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        ViewBag.Scope = scope;

        if (descriptor.Properties.Count > 0)
        {
            ViewBag.Claims = descriptor.Properties["claims"].EnumerateArray().Select(e => e.GetString()).ToList();
        }
        else
        {
            ViewBag.Claims = new List<string>();
        }

        ViewBag.Resources = descriptor.Resources;

        return View(descriptor);
    }

    [HttpGet]
    public IActionResult Add()
    {
        return View(new ScopeInputModel());
    }

    [HttpPost]
    public async Task<IActionResult> AddAsync(ScopeInputModel input)
    {
        if (!ModelState.IsValid) return View(input);

        var descriptor = _mapper.Map<OpenIddictScopeDescriptor>(input);
        descriptor.Properties["claims"] = JsonSerializer.SerializeToElement(new string[] { });
        var scope = await _scopeManager.CreateAsync(descriptor);
        _logger.LogInformation("{user} created new scope {scope}", User.Identity.Name, scope.Name);
        return RedirectToAction("View", new { id = scope.Id });
    }

    [HttpGet]
    public async Task<IActionResult> EditAsync(string id)
    {
        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        ViewBag.Scope = scope;

        if (descriptor.Properties.Count > 0)
        {
            ViewBag.Claims = descriptor.Properties["claims"].EnumerateArray().Select(e => e.GetString()).ToList();
        }
        else
        {
            ViewBag.Claims = new List<string>();
        }

        ViewBag.Resources = descriptor.Resources;

        return View(_mapper.Map<ScopeInputModel>(scope));
    }

    [HttpPost]
    public async Task<IActionResult> EditAsync(string id, ScopeInputModel input)
    {
        if (!ModelState.IsValid) return View(input);

        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        _mapper.Map(input, descriptor);
        await _scopeManager.UpdateAsync(scope, descriptor);
        _logger.LogInformation("{user} updated scope {scope}", User.Identity.Name, descriptor.Name);

        return RedirectToAction("View", new { id });
    }

    [HttpGet]
    public async Task<IActionResult> DeleteAsync(string id)
    {
        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null) return NotFound();

        await _scopeManager.DeleteAsync(scope);
        _logger.LogInformation("{user} deleted scope {scope}", User.Identity.Name, id);

        return RedirectToAction("Index");
    }

    public async Task<IActionResult> AddClaimAsync(string scopeId, string claim)
    {
        var scope = await _scopeManager.FindByIdAsync(scopeId);
        if (scope == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        var claims = descriptor.Properties["claims"].EnumerateArray().Select(e => e.GetString()).ToList();
        claims.Add(claim);
        descriptor.Properties["claims"] = JsonSerializer.SerializeToElement(claims);

        await _scopeManager.UpdateAsync(scope, descriptor);
        _logger.LogInformation("{user} added claim {claim} to {scope}", User.Identity.Name, claim, scope.Name);

        return RedirectToAction("View", new { id = scopeId });
    }

    public async Task<IActionResult> RemoveClaimAsync(string scopeId, string claim)
    {
        var scope = await _scopeManager.FindByIdAsync(scopeId);
        if (scope == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        var claims = descriptor.Properties["claims"].EnumerateArray().Select(e => e.GetString()).ToList();
        claims.Remove(claim);
        descriptor.Properties["claims"] = JsonSerializer.SerializeToElement(claims);

        await _scopeManager.UpdateAsync(scope, descriptor);
        _logger.LogInformation("{user} removed claim {claim} from {scope}", User.Identity.Name, claim, scope.Name);

        return RedirectToAction("View", new { id = scopeId });
    }

    public async Task<IActionResult> AddResourceAsync(string scopeId, string resource)
    {
        var scope = await _scopeManager.FindByIdAsync(scopeId);
        if (scope == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        descriptor.Resources.Add(resource);
        await _scopeManager.UpdateAsync(scope, descriptor);
        _logger.LogInformation("{user} added resource {resource} to {scope}", User.Identity.Name, resource, scope.Name);

        return RedirectToAction("View", new { id = scopeId });
    }

    public async Task<IActionResult> RemoveResourceAsync(string scopeId, string resource)
    {
        var scope = await _scopeManager.FindByIdAsync(scopeId);
        if (scope == null) return NotFound();

        var descriptor = new OpenIddictScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        descriptor.Resources.Remove(resource);

        await _scopeManager.UpdateAsync(scope, descriptor);
        _logger.LogInformation("{user} removed resource {resource} from {scope}", User.Identity.Name, resource, scope.Name);

        return RedirectToAction("View", new { id = scopeId });
    }
}