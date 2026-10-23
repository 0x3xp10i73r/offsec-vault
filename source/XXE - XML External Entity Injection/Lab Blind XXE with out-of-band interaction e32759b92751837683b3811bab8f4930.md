# Lab: Blind XXE with out-of-band interaction

This lab has a "Check stock" feature that parses XML input but does not display the result.

You can detect the blind XXE vulnerability by triggering out-of-band interactions with an external domain.

To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

### Note

To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.

![image.png](Lab%20Blind%20XXE%20with%20out-of-band%20interaction/image.png)

![image.png](Lab%20Blind%20XXE%20with%20out-of-band%20interaction/image%201.png)

![image.png](Lab%20Blind%20XXE%20with%20out-of-band%20interaction/image%202.png)

![image.png](Lab%20Blind%20XXE%20with%20out-of-band%20interaction/image%203.png)

![image.png](Lab%20Blind%20XXE%20with%20out-of-band%20interaction/image%204.png)

![image.png](Lab%20Blind%20XXE%20with%20out-of-band%20interaction/image%205.png)

![image.png](Lab%20Blind%20XXE%20with%20out-of-band%20interaction/image%206.png)