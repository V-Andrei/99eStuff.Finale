using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace _99eStuff.Models
{
    public class UsersLoginViewModel
    {
        public int UserID { get; set; }

        [DisplayName("User Name")]
        [Required(ErrorMessage = "This field is required.")]
        public string UserName { get; set; }

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "This field is required.")]
        public string Password { get; set; }

        [Required]
        public string Mail { get; set; }
        [Required]
        public string NameClient { get; set; }

        public string LoginErrorMessage { get; set; }
    }
}