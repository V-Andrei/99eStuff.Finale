using _99eStuff.Models;
using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Web.Mvc;

namespace _99eStuff.Controllers
{
    public class ContactController : Controller
    {
        public ActionResult Contact()
        {
            return View();
        }
        public ActionResult ContactSent()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Contact(ContactViewModel customer)
        {
            string constr = ConfigurationManager.ConnectionStrings["ProductsModel"].ConnectionString;
            using (SqlConnection con = new SqlConnection(constr))
            {
                string query = "INSERT INTO dbo.ContactData(NameClient, Mail, City,Message) VALUES(@NameClient, @Mail, @City, @Message)";
                query += " SELECT SCOPE_IDENTITY()";
                using (SqlCommand cmd = new SqlCommand(query))
                {
                    cmd.Connection = con;
                    con.Open();
                    cmd.Parameters.AddWithValue("@NameClient", customer.NameClient);
                    cmd.Parameters.AddWithValue("@Mail", customer.Mail);
                    cmd.Parameters.AddWithValue("@City", customer.City);
                    cmd.Parameters.AddWithValue("@Message", customer.Message);
                    customer.IdClient = Convert.ToInt32(cmd.ExecuteScalar());
                    con.Close();
                }
            }

            return RedirectToAction("ContactSent", "Contact"); ;
        }
    }
}