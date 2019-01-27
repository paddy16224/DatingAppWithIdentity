using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using System;
using System.IdentityModel.Tokens.Jwt;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace DatingApp.API.Controllers
{
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;
        public AuthController(IConfiguration config,
        IMapper mapper, UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _mapper = mapper;
            _config = config;
        }

    [HttpPost("register")]
    public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
    {
       
        User userToCreate = _mapper.Map<User>(userForRegisterDto);
        var result = await _userManager.CreateAsync(userToCreate, userForRegisterDto.Password);
        var userToReturn = _mapper.Map<UserForDetailedDto>(userToCreate);

        if(result.Succeeded)
        {
            return CreatedAtRoute("GetUser", 
                new { contorller = "Users", id = userToCreate.Id }, userToReturn); 
        }
        return BadRequest(result.Errors);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
    {
        var user = await _userManager.FindByNameAsync(userForLoginDto.Username);
        var result = await _signInManager
                .CheckPasswordSignInAsync(user, userForLoginDto.Password, false);

        if(result.Succeeded){
            var appUser = await _userManager.Users.Include(p=>p.Photos)
                    .FirstOrDefaultAsync(u => u.NormalizedUserName == userForLoginDto.Username.ToUpper());

            var userToReturn = _mapper.Map<UserForListDto>(appUser);
            return Ok(new
            {
                token = await GenerateJwtToken(appUser),
                user = userToReturn
            });
        }
        return Unauthorized();
    }

    private async Task<string> GenerateJwtToken(User user)
    {
        var claims = new List<Claim>{
                new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                new Claim(ClaimTypes.Name,user.UserName)
            };
        var roles = await _userManager.GetRolesAsync(user);

        foreach( var role in roles){
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        // Creating a security key
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

        // key is using with signing crediential and encrypting it with hashing algorithm
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        // Creating token and passing claims and other information.
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.AddDays(1),
            SigningCredentials = creds
        };

        // With the help of token handler we are creating toking by passing token descriptor.
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}
}