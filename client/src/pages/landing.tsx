import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Database, Lock, Upload, Search, Zap } from "lucide-react";

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="container mx-auto px-4 py-8">
        {/* Hero Section */}
        <div className="text-center py-20">
          <h1 className="text-6xl font-black mb-6">
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              SecureGallery Pro
            </span>
          </h1>
          <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto">
            Advanced media management platform with enterprise-grade security, 
            multi-database support, and intelligent categorization for your digital assets.
          </p>
          <Button 
            size="lg" 
            className="text-lg px-8 py-6" 
            onClick={() => window.location.href = '/api/login'}
            data-testid="button-login"
          >
            Get Started - Sign In
          </Button>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 py-16">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <Shield className="w-6 h-6 text-primary" />
                Enterprise Security
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                AES-256 encryption, secure vault system, role-based access control, 
                and comprehensive audit logging for maximum data protection.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <Database className="w-6 h-6 text-primary" />
                Multi-Database Support
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Compatible with PostgreSQL, SQLite, and SQL Server Express. 
                Binary file storage with metadata indexing and seamless switching.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <Lock className="w-6 h-6 text-accent" />
                Encrypted Vault
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Secure vault section with separate access controls, 
                client-side encryption, and biometric authentication support.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <Upload className="w-6 h-6 text-primary" />
                Smart Import System
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Google Photos integration, batch processing, SHA-256 duplicate detection, 
                and automatic thumbnail generation with metadata extraction.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <Search className="w-6 h-6 text-primary" />
                Advanced Categorization
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Hierarchical folder system, intelligent tagging, powerful search capabilities, 
                and automated organization based on metadata analysis.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <Zap className="w-6 h-6 text-primary" />
                Smart Navigation System
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Keyboard shortcuts for quick navigation, responsive thumbnails, autoplay videos, 
                and optimized performance for large collections up to 200GB.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Technical Specifications */}
        <div className="bg-card rounded-lg border border-border p-8 my-16">
          <h2 className="text-3xl font-bold mb-6 text-center">Technical Specifications</h2>
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-xl font-semibold mb-4 text-primary">Security Features</h3>
              <ul className="space-y-2 text-muted-foreground">
                <li>• AES-256-GCM encryption for sensitive content</li>
                <li>• SHA-256 hash-based duplicate detection</li>
                <li>• Role-based access control (RBAC)</li>
                <li>• Secure session management</li>
                <li>• Comprehensive activity logging</li>
                <li>• Biometric authentication support</li>
              </ul>
            </div>
            <div>
              <h3 className="text-xl font-semibold mb-4 text-primary">Performance & Scalability</h3>
              <ul className="space-y-2 text-muted-foreground">
                <li>• Support for 200GB+ media collections</li>
                <li>• React Virtual for large dataset rendering</li>
                <li>• Efficient binary storage in database</li>
                <li>• Automatic thumbnail generation</li>
                <li>• Lazy loading and caching strategies</li>
                <li>• Multi-database abstraction layer</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Call to Action */}
        <div className="text-center py-16">
          <h2 className="text-4xl font-bold mb-6">Ready to Secure Your Media?</h2>
          <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            Join thousands of professionals who trust SecureGallery Pro 
            for their media management and security needs.
          </p>
          <Button 
            size="lg" 
            className="text-lg px-8 py-6"
            onClick={() => window.location.href = '/api/login'}
            data-testid="button-cta-login"
          >
            Access Your Gallery
          </Button>
        </div>
      </div>
    </div>
  );
}
