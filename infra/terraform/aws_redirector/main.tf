data "aws_vpc" "default" {
  default = true
}

data "aws_ami" "ubuntu" {
  owners = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  most_recent = true
}

resource "aws_security_group" "redirector_sg" {
  name        = "vantablack-redirector-sg"
  description = "Allow HTTP/HTTPS/WireGuard"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  ingress {
    description = "WireGuard"
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = var.allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  user_data = templatefile("${path.module}/user_data.sh", {
    domain = var.domain
    email  = var.letsencrypt_email
    wg_cidr = var.wg_cidr
    wg_server_address = var.wg_server_address
    wg_peer_address = var.wg_peer_address
    wg_peer_allowed_ips = var.wg_peer_allowed_ips
    wg_peer_public_key = var.wg_peer_public_key
  })
}

resource "aws_instance" "redirector" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.redirector_sg.id]
  user_data              = local.user_data
  tags = {
    Name = "Vantablack-Redirector"
  }
}
