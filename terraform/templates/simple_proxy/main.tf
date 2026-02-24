terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  description = "DigitalOcean API Token"
  type        = string
  sensitive   = true
}

variable "droplet_name" {
  description = "Name for the droplet"
  type        = string
  default     = "vanta-proxy-ephimeral"
}

provider "digitalocean" {
  token = var.do_token
}

resource "digitalocean_droplet" "proxy" {
  image    = "ubuntu-22-04-x64"
  name     = var.droplet_name
  region   = "nyc3" # New York 3
  size     = "s-1vcpu-1gb" # Smallest size
  
  # Example user data to install a simple web server for testing
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get -y install nginx
              echo "VANTABLACK Proxy Node" > /var/www/html/index.html
              EOF
}

output "droplet_ip" {
  value = digitalocean_droplet.proxy.ipv4_address
}
