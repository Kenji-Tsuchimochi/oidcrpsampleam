package oidc;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Servlet implementation class OIDCIndex
 */
@WebServlet({ "/index", "/" })
public class OIDCIndex extends HttpServlet {
	private static final long serialVersionUID = 1L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public OIDCIndex() {
        super();
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		HttpSession sess = req.getSession();
		if(sess != null) {
			sess.invalidate();
		}
		sess = req.getSession(true);

		sess.setAttribute("state", UUID.randomUUID().toString());
		sess.setAttribute("nonce", UUID.randomUUID().toString());

		res.setContentType("text/html");
		res.setCharacterEncoding("UTF-8");

		PrintWriter pw = new PrintWriter(res.getOutputStream());
		pw.println("<!DOCTYPE html>");
		pw.println("<html lang=\"ja\">");
		pw.println("<head>");
		pw.println("<title>OpenID Connect RPサンプル</title>");
		pw.println("</head>");
		pw.println("<body>");
		pw.println("<a href=\"" + req.getContextPath() + "/start" + "\">Yahoo! ID連携 で認証</a>");
		pw.println("</body>");
		pw.println("</html>");
		pw.flush();
		pw.close();
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}
}
