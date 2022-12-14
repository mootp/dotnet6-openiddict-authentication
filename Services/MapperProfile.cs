using authServer.Entities;
using authServer.Models;
using AutoMapper;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace authServer.Services;

public class MapperProfile : Profile
{
    public MapperProfile()
    {
        CreateMap<RegistrationInputModel, ApplicationUser>();
        CreateMap<ApplicationUser, EditUserInputModel>();
        CreateMap<ScopeInputModel, OpenIddictScopeDescriptor>();
        CreateMap<OpenIddictEntityFrameworkCoreScope, ScopeInputModel>();
        CreateMap<RoleInputModel, ApplicationRole>();
        CreateMap<ApplicationRole, RoleInputModel>();

        CreateMap<string, HashSet<Uri>>().ConvertUsing(new StringToUrisConverter());
        CreateMap<HashSet<Uri>, string>().ConvertUsing(new UrisToStringConverter());

        CreateMap<ApplicationInputModel, OpenIddictApplicationDescriptor>()
            .ForMember(dest => dest.ClientSecret, opt => opt.Condition(src => src.IsNewClientSecret))
            .ForMember(dest => dest.Type, opt => opt.MapFrom((src, dest) =>
            {
                if (!src.IsNewClientSecret) return dest.Type;
                return string.IsNullOrEmpty(src.ClientSecret) ?
                    OpenIddictConstants.ClientTypes.Public : OpenIddictConstants.ClientTypes.Confidential;
            }));

        CreateMap<OpenIddictApplicationDescriptor, ApplicationInputModel>()
            .ForMember(dest => dest.ClientSecret, opt => opt.MapFrom(src =>
                string.IsNullOrEmpty(src.ClientSecret) ? src.ClientSecret : "********"))
            .ForMember(dest => dest.IsPkce, opt => opt.MapFrom(src =>
                src.Requirements.Contains(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange)));
    }

    public class StringToUrisConverter : ITypeConverter<string, HashSet<Uri>>
    {
        public HashSet<Uri> Convert(string source, HashSet<Uri> destination, ResolutionContext context)
        {
            destination.Clear();
            if (!string.IsNullOrEmpty(source))
            {
                var uris = source.Split(new string[] { ",", " ", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => new Uri(s));
                destination.UnionWith(uris);
            }
            return destination;
        }
    }

    public class UrisToStringConverter : ITypeConverter<HashSet<Uri>, string>
    {
        public string Convert(HashSet<Uri> source, string destination, ResolutionContext context)
        {
            return string.Join('\n', source);
        }
    }
}
