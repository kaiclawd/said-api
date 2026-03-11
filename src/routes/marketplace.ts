import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = new Hono();

// ========================================
// LISTINGS
// ========================================

/**
 * GET /marketplace/listings
 * Browse all agent listings with filters
 */
app.get('/listings', async (c) => {
  const { skill, minRating, maxPrice, available } = c.req.query();

  const where: any = {};
  
  if (skill) {
    where.skills = { has: skill };
  }
  
  if (minRating) {
    where.rating = { gte: parseFloat(minRating) };
  }
  
  if (maxPrice) {
    where.OR = [
      { priceSOL: { lte: parseFloat(maxPrice) } },
      { priceUSDC: { lte: parseFloat(maxPrice) } },
      { hourlyRate: { lte: parseFloat(maxPrice) } },
    ];
  }
  
  if (available !== undefined) {
    where.available = available === 'true';
  }

  const listings = await prisma.agentListing.findMany({
    where,
    include: {
      _count: {
        select: { jobs: true, reviews: true }
      }
    },
    orderBy: [
      { featured: 'desc' },
      { rating: 'desc' },
      { createdAt: 'desc' },
    ]
  });

  return c.json({ listings });
});

/**
 * GET /marketplace/listings/:id
 * Get single listing with full details
 */
app.get('/listings/:id', async (c) => {
  const { id } = c.req.param();

  const listing = await prisma.agentListing.findUnique({
    where: { id },
    include: {
      reviews: {
        orderBy: { createdAt: 'desc' },
        take: 10
      },
      _count: {
        select: { jobs: true }
      }
    }
  });

  if (!listing) {
    return c.json({ error: 'Listing not found' }, 404);
  }

  // Fetch agent data from SAID
  const agent = await prisma.agent.findUnique({
    where: { wallet: listing.agentWallet },
    select: {
      wallet: true,
      name: true,
      description: true,
      image: true,
      isVerified: true,
      passportMint: true,
      reputationScore: true,
      twitter: true,
      website: true,
    }
  });

  return c.json({ listing, agent });
});

/**
 * POST /marketplace/listings
 * Create new listing (requires verified SAID passport)
 */
app.post('/listings', async (c) => {
  const body = await c.req.json();
  const { agentWallet, title, description, skills, priceSOL, priceUSDC, hourlyRate } = body;

  // Verify agent has SAID passport
  const agent = await prisma.agent.findUnique({
    where: { wallet: agentWallet },
    select: { passportMint: true, isVerified: true }
  });

  if (!agent || !agent.passportMint) {
    return c.json({ 
      error: 'Agent must have verified SAID passport to create listing',
      requiresPassport: true 
    }, 403);
  }

  // Create listing
  const listing = await prisma.agentListing.create({
    data: {
      agentWallet,
      title,
      description,
      skills: skills || [],
      priceSOL,
      priceUSDC,
      hourlyRate,
      available: true,
    }
  });

  return c.json({ listing }, 201);
});

/**
 * PUT /marketplace/listings/:id
 * Update listing
 */
app.put('/listings/:id', async (c) => {
  const { id } = c.req.param();
  const body = await c.req.json();
  const { title, description, skills, priceSOL, priceUSDC, hourlyRate, available } = body;

  const listing = await prisma.agentListing.update({
    where: { id },
    data: {
      ...(title && { title }),
      ...(description && { description }),
      ...(skills && { skills }),
      ...(priceSOL !== undefined && { priceSOL }),
      ...(priceUSDC !== undefined && { priceUSDC }),
      ...(hourlyRate !== undefined && { hourlyRate }),
      ...(available !== undefined && { available }),
    }
  });

  return c.json({ listing });
});

/**
 * DELETE /marketplace/listings/:id
 * Delete listing
 */
app.delete('/listings/:id', async (c) => {
  const { id } = c.req.param();

  await prisma.agentListing.delete({
    where: { id }
  });

  return c.json({ success: true });
});

// ========================================
// JOBS
// ========================================

/**
 * POST /marketplace/jobs
 * Create job request
 */
app.post('/jobs', async (c) => {
  const body = await c.req.json();
  const { listingId, clientWallet, title, description, budgetSOL, budgetUSDC } = body;

  // Verify listing exists
  const listing = await prisma.agentListing.findUnique({
    where: { id: listingId }
  });

  if (!listing) {
    return c.json({ error: 'Listing not found' }, 404);
  }

  if (!listing.available) {
    return c.json({ error: 'Listing is not available' }, 400);
  }

  const job = await prisma.job.create({
    data: {
      listingId,
      clientWallet,
      agentWallet: listing.agentWallet,
      title,
      description,
      budgetSOL,
      budgetUSDC,
      status: 'pending',
    }
  });

  return c.json({ job }, 201);
});

/**
 * GET /marketplace/jobs/:id
 * Get job details
 */
app.get('/jobs/:id', async (c) => {
  const { id } = c.req.param();

  const job = await prisma.job.findUnique({
    where: { id },
    include: {
      listing: true,
      review: true,
    }
  });

  if (!job) {
    return c.json({ error: 'Job not found' }, 404);
  }

  return c.json({ job });
});

/**
 * PUT /marketplace/jobs/:id/accept
 * Agent accepts job
 */
app.put('/jobs/:id/accept', async (c) => {
  const { id } = c.req.param();

  const job = await prisma.job.update({
    where: { id },
    data: {
      status: 'accepted',
      acceptedAt: new Date(),
    }
  });

  return c.json({ job });
});

/**
 * PUT /marketplace/jobs/:id/start
 * Mark job as started
 */
app.put('/jobs/:id/start', async (c) => {
  const { id } = c.req.param();

  const job = await prisma.job.update({
    where: { id },
    data: {
      status: 'in_progress',
      startedAt: new Date(),
    }
  });

  return c.json({ job });
});

/**
 * PUT /marketplace/jobs/:id/complete
 * Mark job as complete (triggers payment release)
 */
app.put('/jobs/:id/complete', async (c) => {
  const { id } = c.req.param();
  const body = await c.req.json();
  const { releaseTx } = body;

  const job = await prisma.job.update({
    where: { id },
    data: {
      status: 'completed',
      completedAt: new Date(),
      releaseTx,
    }
  });

  // Update listing stats
  await prisma.agentListing.update({
    where: { id: job.listingId },
    data: {
      jobsCompleted: { increment: 1 },
      totalEarned: { 
        increment: job.budgetSOL || job.budgetUSDC || 0 
      },
    }
  });

  return c.json({ job });
});

/**
 * PUT /marketplace/jobs/:id/dispute
 * Open dispute
 */
app.put('/jobs/:id/dispute', async (c) => {
  const { id } = c.req.param();

  const job = await prisma.job.update({
    where: { id },
    data: {
      status: 'disputed',
    }
  });

  return c.json({ job });
});

// ========================================
// REVIEWS
// ========================================

/**
 * POST /marketplace/reviews
 * Submit review (after job completion)
 */
app.post('/reviews', async (c) => {
  const body = await c.req.json();
  const { jobId, rating, comment, reviewerWallet, signature } = body;

  // Verify job exists and is completed
  const job = await prisma.job.findUnique({
    where: { id: jobId }
  });

  if (!job) {
    return c.json({ error: 'Job not found' }, 404);
  }

  if (job.status !== 'completed') {
    return c.json({ error: 'Can only review completed jobs' }, 400);
  }

  if (job.clientWallet !== reviewerWallet) {
    return c.json({ error: 'Only client can review this job' }, 403);
  }

  // Create review
  const review = await prisma.review.create({
    data: {
      jobId,
      listingId: job.listingId,
      rating,
      comment,
      reviewerWallet,
      signature,
    }
  });

  // Update listing rating (recalculate average)
  const allReviews = await prisma.review.findMany({
    where: { listingId: job.listingId },
    select: { rating: true }
  });

  const avgRating = allReviews.reduce((sum, r) => sum + r.rating, 0) / allReviews.length;

  await prisma.agentListing.update({
    where: { id: job.listingId },
    data: { rating: avgRating }
  });

  return c.json({ review }, 201);
});

/**
 * GET /marketplace/listings/:id/reviews
 * Get all reviews for a listing
 */
app.get('/listings/:id/reviews', async (c) => {
  const { id } = c.req.param();

  const reviews = await prisma.review.findMany({
    where: { listingId: id },
    orderBy: { createdAt: 'desc' }
  });

  return c.json({ reviews });
});

// ========================================
// STATS
// ========================================

/**
 * GET /marketplace/stats
 * Platform-wide stats
 */
app.get('/stats', async (c) => {
  const [
    totalListings,
    totalJobs,
    completedJobs,
    totalReviews,
    activeListings,
  ] = await Promise.all([
    prisma.agentListing.count(),
    prisma.job.count(),
    prisma.job.count({ where: { status: 'completed' } }),
    prisma.review.count(),
    prisma.agentListing.count({ where: { available: true } }),
  ]);

  // Calculate total value transacted
  const jobs = await prisma.job.findMany({
    where: { status: 'completed' },
    select: { budgetSOL: true, budgetUSDC: true }
  });

  const totalValueSOL = jobs.reduce((sum, j) => sum + (j.budgetSOL || 0), 0);
  const totalValueUSDC = jobs.reduce((sum, j) => sum + (j.budgetUSDC || 0), 0);

  return c.json({
    totalListings,
    activeListings,
    totalJobs,
    completedJobs,
    totalReviews,
    totalValueSOL,
    totalValueUSDC,
  });
});

/**
 * GET /marketplace/agents/:wallet/stats
 * Agent-specific stats
 */
app.get('/agents/:wallet/stats', async (c) => {
  const { wallet } = c.req.param();

  const listings = await prisma.agentListing.findMany({
    where: { agentWallet: wallet }
  });

  const jobs = await prisma.job.findMany({
    where: { agentWallet: wallet }
  });

  const completedJobs = jobs.filter(j => j.status === 'completed');
  const totalEarned = completedJobs.reduce((sum, j) => sum + (j.budgetSOL || j.budgetUSDC || 0), 0);

  const reviews = await prisma.review.findMany({
    where: { 
      listingId: { in: listings.map(l => l.id) }
    }
  });

  const avgRating = reviews.length > 0
    ? reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length
    : null;

  return c.json({
    totalListings: listings.length,
    activeListings: listings.filter(l => l.available).length,
    totalJobs: jobs.length,
    completedJobs: completedJobs.length,
    totalEarned,
    totalReviews: reviews.length,
    avgRating,
  });
});

export default app;
