using System.Data;
using System.Data.SqlClient;
using System.Configuration;

namespace _99eStuff.Data
{
    public class ConnectionData
    {
        SqlCommand cmd;
        SqlDataAdapter da;
      
        public static SqlConnection connect()
        {
            string connection = ConfigurationManager.ConnectionStrings["ProductsModel"].ConnectionString;
            SqlConnection con = new SqlConnection(connection);
            if(con.State==ConnectionState.Open)
            {
                con.Close();
            }
            else
            {
                con.Open();
            }
            return con;
        }

        public bool Opperation(string query)
        {
            cmd = new SqlCommand(query, ConnectionData.connect());
            int x= cmd.ExecuteNonQuery();
            if(x==1)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public DataTable GetAll(string query)
        {
            da = new SqlDataAdapter(query, ConnectionData.connect());
            DataTable dt = new DataTable();
            da.Fill(dt);
            return dt;
        }
    }
}
