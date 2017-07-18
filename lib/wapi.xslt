<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/suite">
    <html>
      <head>
      <style type="text/css">
      body {
        font:normal 68% verdana,arial,helvetica;
        color:#000000;
      }
      table tr td, table tr th {
          font-size: 68%;
      }
      table.details tr th{
        font-weight: bold;
        text-align:left;
        background:#a6caf0;
      }
      table.details tr td{
        background:#eeeee0;
      }

      p {
        line-height:1.5em;
        margin-top:0.5em; margin-bottom:1.0em;
      }
      h1 {
        margin: 0px 0px 5px; font: 165% verdana,arial,helvetica
      }
      h2 {
        margin-top: 1em; margin-bottom: 0.5em; font: bold 125% verdana,arial,helvetica
      }
      h3 {
        margin-bottom: 0.5em; font: bold 115% verdana,arial,helvetica
      }
      h4 {
        margin-bottom: 0.5em; font: bold 100% verdana,arial,helvetica
      }
      h5 {
        margin-bottom: 0.5em; font: bold 100% verdana,arial,helvetica
      }
      h6 {
        margin-bottom: 0.5em; font: bold 100% verdana,arial,helvetica
      }
      .Error {
        font-weight:bold; color:red;
      }
      .Failure {
        font-weight:bold; color:purple;
      }
      .Properties {
        text-align:right;
      }
      .Highlight {
        font-weight:bold; color:green;
      }
      </style>
      </head>
      <body>
        <h1><xsl:value-of select="name" /></h1>
	<hr size="1" />
	<xsl:if test="compatible"><b>Compatible : </b><xsl:value-of select="compatible" /><br /></xsl:if>
        <xsl:apply-templates select="pass" />
      </body>
     </html>
  </xsl:template>

  <xsl:template match="pass">
    <h2><xsl:value-of select="version" /> Summary</h2>
    <table class="details" border="0" cellpadding="5" cellspacing="2" width="95%">
      <tr valign="top"><th>Total</th><th>Passed</th><th>Failed</th><th>Total Time (Seconds)</th></tr> 
      <xsl:apply-templates select="summary" />
    </table><hr size="1" width="95%" align="left" />                    
    <table class="details" border="0" cellpadding="5" cellspacing="2" width="95%">
      <tr valign="top"><th>ID</th><th>TestCase Name</th><th>Time Taken (Seconds)</th><th>Status</th></tr>
      <xsl:apply-templates select="test" />
    </table>
  </xsl:template>

  <xsl:template match="test">
    <xsl:choose> 
     <xsl:when test="status = 'FAIL'">
      <tr valign="top" class="Error">
      <td><xsl:value-of select="id" /></td>
      <td><xsl:value-of select="name" /></td>
      <td><xsl:value-of select="time" /></td>
      <td>
        <a target="_blank" style="color:red">
          <xsl:attribute name="href">
	    <xsl:value-of select="id"/>.log
          </xsl:attribute>
          <xsl:value-of select="status" />
        </a>
      </td>
      </tr>
     </xsl:when>
     <xsl:otherwise>
      <tr valign="top">
      <td><xsl:value-of select="id" /></td>
      <xsl:choose>
       <xsl:when test="highlight = 'yes'">
        <td valign="top" class="Highlight"><xsl:value-of select="name" /></td>
       </xsl:when>
       <xsl:otherwise>
        <td><xsl:value-of select="name" /></td>
       </xsl:otherwise>
      </xsl:choose>
      <td><xsl:value-of select="time" /></td>
      <td>
        <a target="_blank">
          <xsl:attribute name="href">
	    <xsl:value-of select="id"/>.log
          </xsl:attribute>
          <xsl:value-of select="status" />
        </a>
      </td>
      </tr>
     </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="summary">
    <xsl:choose>
      <xsl:when test="fail &gt; 0">
        <tr valign="top" class="Failure">
          <td><b><xsl:value-of select="total" /></b></td>
          <td><b><xsl:value-of select="pass" /></b></td>
          <td><b><xsl:value-of select="fail" /></b></td>
	  <td><b><xsl:value-of select="total_time" /></b></td>
        </tr>
      </xsl:when>
      <xsl:otherwise>
        <tr valign="top">
          <td><b><xsl:value-of select="total" /></b></td>
          <td><b><xsl:value-of select="pass" /></b></td>
          <td><b><xsl:value-of select="fail" /></b></td>
	  <td><b><xsl:value-of select="total_time" /></b></td>
        </tr>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>                      

</xsl:stylesheet>
