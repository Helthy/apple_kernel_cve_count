#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import json
import codecs
import os
# Use python3

# Set 1 for output
err = 0
print_attributes = 0
create_output = 0
print_out = 1

#Change to analyse a different version. iOS 9 to iOS 13 works.
lookfor = "iOS 12"
attributes =[]
impacts = []      
links =[]
names =[]

kernel = 0
global text
text = ""

# Output
def out(string):
	global text
	text = text + string + "\n"
	if print_out:
		print(string)

def parsehtml(string):
	find = string.find("</a>") #
	
	if find < 0:
		if err:
			out("Error: " + string) #There is no link to a separate document = No information available
	else:
		
		link = string[:find]
		start1 = "<a href=\"" #The link contains also information about the fixed software (iOS / macOS / Safari / iTunes...)
		find1 = link.find(start1)
		
		if find1 > 0:
			link1 = link[find1+len(start1):]
			parts = link1.split("\">")
			if len(parts) > 0:
				html_link = parts[0]
				name = parts[1]
				find4 = name.find(lookfor) #Only selected version is analysed.
				if find4 > -1:
					links.append(html_link)
					names.append(name)
					out(name + "  ->  " + html_link)
			else:
				if err:
					out("Error2: "+ string)
		else:
			if err:
				out("Error1: " + string)

def getHTMLfiles():
	url = "https://support.apple.com/en-EN/HT201222" #Basefile for all Apple Security Updates
	
	# start = Begin table of security updates
	start = "<tbody><tr><th><p>Name and information link</p>\n</th>\n<th><p>Available for</p>\n</th>\n<th><p>Release&nbsp;date</p>\n</th>\n</tr>"
	
	# end = End of the table
	end = "</tbody></table></div>"
	
	base = requests.get(url)
	html = base.text
	find1 = html.find(start) 
	
	if find1 > -1:

		html_2 =html[find1+len(start):]
		find2 = html_2.find(end)
		
		if find2 > -1:
		
			html_final = html_2[:find2] #html_final contains now the table contents
			delimiter = "</tr>" #every table row ends with a </tr>
			find3 = html_final.find(delimiter)
		
			while find3 > -1:
		
				parse_html = html_final[:find3]

				parsehtml(parse_html) # Parses every single row = every security update

				html_final = html_final[find3+len(delimiter):]
				find3 = html_final.find(delimiter)

#Parse a single CVE Line
def parsecve(string):
	attribute = "</strong></p>" #End of a single attribute
	availablefor = "<p style=\"margin-left: 40px;\">" #Begin Attribute Available for:
	impact = "Impact:" #Begin Attribute Impact: 
	cve = "<p style=\"margin-left: 40px;\">" #Begin Attribute CVE:
	date_added ="<p style=\"margin-left: 40px;\"><span class=\"note\">" #Begin Date changed.
	
	find_a = string.find(attribute) # Finds the components of the OS
	kernelcount = 0
	
	if find_a > -1:
		attribute = string[:find_a]
		string = string[find_a+len(attribute):]
		
		find_a = string.find(impact)
		string = string[find_a:]
		find_a = string.find("</p>")
		impact = string[:find_a]
		if len(impact)>0: #When no impact is found no vulnerability is closed.
			if attribute == "Kernel":
						kernelcount = kernelcount + 1
			else:
				find = impact.find("kernel")
				if find > -1:
					kernelcount = kernelcount + 1
				else:
					find = impact.find("Kernel")
					if find > -1:
						kernelcount = kernelcount + 1
			attributes.append(attribute)
			impacts.append(impact)
	return kernelcount


start = "<div><p><span class=\"note\">"
end = "<p><strong>"
ende ="</div>"


# Parse single HTML Files
ios = 0
getHTMLfiles()

while ios < len(links):
	
	data = requests.get(links[ios])
	html=data.text
	out("Parsing: " + names[ios])
	find1 = html.find(start)

	if find1 > -1:
		html_2 =html[find1+len(start):]
		find2 = html_2.find(end)
		if find2 > -1:
			html_final = html_2[find2+len(end):]
			delimiter = "<p><strong>" # Every fixed vulnerability starts with a <p><strong>
			find3 = html_final.find(delimiter)
			while find3 > -1:
				parse_html = html_final[:find3]
				kernel = kernel + parsecve(parse_html)
				html_final = html_final[find3+len(delimiter):]
				find3 = html_final.find(delimiter)
			find3 = html_final.find(delimiter)
			
			if find3 > -1: #Analyse last row
				kernel = kernel + parsecve(html_final[:find3])
			else:
				if err:
					out("Error - No </div> found")
	ios = ios + 1

out("kernel: " + str(kernel))
out("Non kernel: " + str(len(attributes)-kernel))
out("Total: " + str(len(attributes)))


if print_attributes:
	if len(attributes) == len(impacts):
		i = 0
		while i < len(attributes):
			out(attributes[i] +  " -> " + impacts[i])
			i = i +1 
	else:
		if err:
			out("Error length attributes != length impacts")

if create_output:
	output=codecs.open("output.txt",'w','utf-8')
	output.write(text)
	output.close()









